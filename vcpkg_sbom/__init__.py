import argparse
import collections
import datetime
import hashlib
import io
import json
import os
import pathlib
import re
import typing
import uuid

import rich
import rich.panel
import rich.progress
import spdx_tools.spdx.document_utils
import spdx_tools.spdx.model as spdx
import spdx_tools.spdx.parser.parse_anything
import spdx_tools.spdx.spdx_element_utils
import spdx_tools.spdx.validation
import spdx_tools.spdx.validation.uri_validators
import spdx_tools.spdx.writer.write_anything
import toolz
from rich.table import Table as RichTable


# NOTE: from https://github.com/Textualize/rich/discussions/482
class TableProgress(rich.progress.Progress):
    def __init__(self, table_max_rows: int, name: str, *args, **kwargs) -> None:
        self.results = collections.deque(maxlen=table_max_rows)
        self.name = name
        self.update_table()
        super().__init__(*args, **kwargs)

    def update_table(self, result: typing.Optional[typing.Tuple[str]] = None):
        if result is not None:
            self.results.append(result)
        table = RichTable()
        table.add_column("ID")
        table.add_column(self.name, width=80)

        for row_cells in self.results:
            table.add_row(*row_cells)

        self.table = table

    def get_renderable(
        self,
    ) -> typing.Union[rich.console.ConsoleRenderable, rich.console.RichCast, str]:
        renderable = rich.console.Group(self.table, *self.get_renderables())
        return renderable


def _add_vcpkg_spdx(
    doc: spdx.Document,
    spdx_json_paths: typing.Sequence[pathlib.Path],
    pbar: TableProgress,
) -> typing.Tuple[typing.Mapping[str, str], typing.List[str]]:
    unique_ids = collections.defaultdict(lambda: 0)
    license_info = {}
    root_pkg_ids = []
    total_spdx = len(spdx_json_paths)
    task = pbar.add_task("Merging spdx: ", total=total_spdx)
    for idx, spdx_json_path in enumerate(spdx_json_paths):
        pkg_name = spdx_json_path.parts[-2]
        if pkg_name.startswith("vcpkg-") or pkg_name.endswith("-uninstall"):
            pbar.update(task, advance=1)
            continue
        spdx_i = spdx_tools.spdx.parser.parse_anything.parse_file(str(spdx_json_path))

        # Identify the binary package (port GENERATES binary) before IDs are remapped
        _original_port_id = spdx_i.packages[0].spdx_id if spdx_i.packages else None
        _port_version = spdx_i.packages[0].version if spdx_i.packages else None
        _original_pkg_ids = {pkg.spdx_id for pkg in spdx_i.packages}
        _binary_pkg_id = None
        if _original_port_id:
            for _rel in spdx_i.relationships:
                if (
                    _rel.spdx_element_id == _original_port_id
                    and _rel.relationship_type == spdx.RelationshipType.GENERATES
                    and _rel.related_spdx_element_id in _original_pkg_ids
                ):
                    _binary_pkg_id = _rel.related_spdx_element_id
                    break

        temp_ids = {}
        for spdx_pkg in spdx_i.packages:
            if spdx_pkg.spdx_id == _binary_pkg_id and _port_version:
                spdx_pkg.version = _port_version
            if not isinstance(
                spdx_pkg.download_location, (spdx.SpdxNoAssertion, spdx.SpdxNone)
            ) and spdx_tools.spdx.validation.uri_validators.validate_uri(
                spdx_pkg.download_location
            ):
                if spdx_pkg.download_location == "git+@":
                    spdx_pkg.download_location = spdx.SpdxNoAssertion()
            if isinstance(spdx_pkg.license_declared, spdx.SpdxNoAssertion) and not isinstance(
                spdx_pkg.license_concluded, (spdx.SpdxNoAssertion, spdx.SpdxNone)
            ):
                spdx_pkg.license_declared = spdx_pkg.license_concluded
            temp_ids[spdx_pkg.spdx_id] = unique_ids[spdx_pkg.spdx_id]
            unique_ids[spdx_pkg.spdx_id] += 1
            spdx_pkg.spdx_id = f"{spdx_pkg.spdx_id}-{temp_ids[spdx_pkg.spdx_id]}"
            license_info[spdx_pkg.name] = str(spdx_pkg.license_concluded)

        files_to_merge = []
        for spdx_file in spdx_i.files:
            algos = set(
                toolz.map(
                    lambda c: c.algorithm,
                    toolz.unique(spdx_file.checksums, lambda c: c.algorithm),
                )
            )
            if spdx.ChecksumAlgorithm.SHA1 not in algos:
                file_path = pathlib.Path(spdx_file.name)
                if not file_path.is_absolute():
                    # vcpkg now uses paths relative to the triplet root for installed
                    # files (./include/..., ./share/..., etc.) and relative to the
                    # package share dir for port files (./portfile.cmake, ./vcpkg.json)
                    triplet_root = spdx_json_path.parent.parent.parent
                    resolved = triplet_root / file_path
                    if not resolved.exists():
                        resolved = spdx_json_path.parent / file_path
                    file_path = resolved
                if not file_path.exists():
                    # Can't compute required SHA1 (file not in vcpkg_installed —
                    # e.g. portfile.cmake, vcpkg.json, patch files live in vcpkg ports dir).
                    # Exclude entirely; the relationship guard on temp_ids drops CONTAINS too.
                    continue
                with open(file_path, "rb") as f:
                    h = hashlib.new("sha1")
                    h.update(f.read())
                    digest = h.hexdigest()
                    # digest = hashlib.file_digest(f, "sha1").hexdigest() # only valid in py > 3.11
                    spdx_file.checksums.append(
                        spdx.Checksum(spdx.ChecksumAlgorithm.SHA1, digest)
                    )
            if not spdx_file.license_info_in_file:
                spdx_file.license_info_in_file = [spdx.SpdxNoAssertion()]
            temp_ids[spdx_file.spdx_id] = unique_ids[spdx_file.spdx_id]
            unique_ids[spdx_file.spdx_id] += 1
            spdx_file.spdx_id = f"{spdx_file.spdx_id}-{temp_ids[spdx_file.spdx_id]}"
            files_to_merge.append(spdx_file)

        rels_to_merge = []
        for spdx_rel in spdx_i.relationships:
            if spdx_rel.spdx_element_id not in temp_ids or spdx_rel.related_spdx_element_id not in temp_ids:
                continue
            spdx_rel.spdx_element_id = (
                f"{spdx_rel.spdx_element_id}-{temp_ids[spdx_rel.spdx_element_id]}"
            )
            spdx_rel.related_spdx_element_id = f"{spdx_rel.related_spdx_element_id}-{temp_ids[spdx_rel.related_spdx_element_id]}"
            rels_to_merge.append(spdx_rel)

        ## merge
        doc.packages.extend(spdx_i.packages)
        doc.files.extend(files_to_merge)
        if _binary_pkg_id and _binary_pkg_id in temp_ids:
            root_pkg_ids.append(f"{_binary_pkg_id}-{temp_ids[_binary_pkg_id]}")
        elif spdx_i.packages:
            root_pkg_ids.append(spdx_i.packages[0].spdx_id)  # fallback to port if no binary
        doc.relationships.extend(rels_to_merge)
        doc.snippets.extend(spdx_i.snippets)
        doc.extracted_licensing_info.extend(spdx_i.extracted_licensing_info)
        doc.annotations.extend(spdx_i.annotations)

        pbar.update(task, advance=1)
        pbar.update_table((f"{idx}", f"{spdx_json_path.parts[-2]}"))
    return license_info, root_pkg_ids


def _add_licenses(
    writer: io.TextIOBase,
    license_paths: typing.Sequence[pathlib.Path],
    pbar: TableProgress,
) -> None:
    total_licenses = len(license_paths)
    task = pbar.add_task("Merging copyrights: ", total=total_licenses)
    for idx, license_path in enumerate(license_paths):
        pkg_name = license_path.parts[-2]
        writer.writelines(
            [
                os.linesep,
                "*" * 80,
                os.linesep,
                "\t" * 5,
                pkg_name,
                os.linesep,
                "*" * 80,
                os.linesep,
            ]
        )
        with open(license_path, "r", errors="ignore") as f:
            writer.write(f.read())
        pbar.update(task, advance=1)


def _parse_args():
    parser = argparse.ArgumentParser(
        "vcpkg-sbom",
        "A software bill of materials extracter and merger for `vcpkg` manifest projects.",
    )
    parser.add_argument(
        "vcpkg_root",
        type=str,
        help="Path to the `vcpkg_installed` folder of your manifest project.",
    )
    parser.add_argument(
        "-t",
        "--triplet",
        type=str,
        default="x64-windows",
        help="The `vcpkg` triplet to use.",
    )
    parser.add_argument(
        "-p",
        "--project",
        type=str,
        default="project",
        help="The project's name that will be used for the merged output files.",
    )
    parser.add_argument(
        "-n",
        "--namespace",
        type=str,
        default="https://spdx.org/spdxdocs/",
        help="The software's namespace to use for the `spdx` file.",
    )
    parser.add_argument(
        "-o",
        "--organization",
        type=str,
        default="org",
        help="The organization or company name to use for the `spdx` file.",
    )
    parser.add_argument(
        "-e",
        "--email",
        type=str,
        default="info@org.com",
        help="The email to use for the `spdx` file.",
    )
    parser.add_argument(
        "-v",
        "--version",
        type=str,
        default=None,
        help="The project version to include in the `spdx` file.",
    )
    parser.add_argument(
        "--project-license",
        type=str,
        default=None,
        help="SPDX license expression for your project (e.g. 'MIT', 'Apache-2.0'). Defaults to NOASSERTION.",
    )
    parser.add_argument(
        "-c",
        "--copyright",
        action="store_true",
        help="Additionally extract and merge all copyright files in a `*.txt` file.",
    )
    parser.add_argument(
        "-l",
        "--license",
        action="store_true",
        help="Additionally extract and merge all license types in a `*.json` file.",
    )
    return parser.parse_args()


def run():
    args = _parse_args()
    vcpkg_triplet_path = pathlib.Path(args.vcpkg_root) / pathlib.Path(args.triplet)
    if not os.path.exists(vcpkg_triplet_path):
        rich.print(
            f"Manifest path [[cyan italic]{vcpkg_triplet_path}[/cyan italic]] [red][bold]does not[/bold] exist[/red], exiting."
        )
        exit(-1)

    spdx_json_paths = set()
    for spdx_json_path in vcpkg_triplet_path.glob("**/share/**/*.spdx.json"):
        # *_, inner_triplet, _, pkg_name, __ = spdx_json_path.parts
        spdx_json_paths.add(spdx_json_path)

    total_spdx = len(spdx_json_paths)
    with TableProgress(table_max_rows=total_spdx, name="Package") as pbar:
        actor = spdx.Actor(spdx.ActorType.ORGANIZATION, args.organization, args.email)
        namespace = f"{args.namespace.rstrip('/')}/{args.project}-{uuid.uuid4()}"
        merged = spdx.Document(
            spdx.CreationInfo(
                "SPDX-2.3",
                "SPDXRef-DOCUMENT",
                args.project,
                namespace,
                [actor],
                datetime.datetime.now(),
            )
        )
        license_info, root_pkg_ids = _add_vcpkg_spdx(merged, spdx_json_paths, pbar)

        if args.project_license:
            import license_expression as le
            _app_license = le.get_spdx_licensing().parse(args.project_license)
        else:
            _app_license = spdx.SpdxNoAssertion()
        app_package = spdx.Package(
            spdx_id="SPDXRef-Application",
            name=args.project,
            version=args.version,
            download_location=spdx.SpdxNoAssertion(),
            supplier=actor,
            files_analyzed=False,
            license_concluded=_app_license,
            license_declared=_app_license,
            copyright_text=spdx.SpdxNoAssertion(),
            primary_package_purpose=spdx.PackagePurpose.APPLICATION,
        )
        merged.packages.insert(0, app_package)
        merged.relationships.append(spdx.Relationship(
            merged.creation_info.spdx_id,
            spdx.RelationshipType.DESCRIBES,
            "SPDXRef-Application",
        ))
        for root_pkg_id in root_pkg_ids:
            merged.relationships.append(spdx.Relationship(
                "SPDXRef-Application",
                spdx.RelationshipType.DEPENDS_ON,
                root_pkg_id,
            ))

    console = rich.console.Console()
    with console.status(
        f"[bold green]Validating & writing `{args.project}.spdx.json` ...",
        spinner="circle",
    ) as status:
        spdx_tools.spdx.writer.write_anything.write_file(
            merged, f"{args.project}.spdx.json", validate=False
        )

    with rich.progress.Progress() as pbar:
        if args.copyright:
            rich.print("Extracting & merging copyrights ...")
            copyright_paths = set()
            for copyright_path in vcpkg_triplet_path.glob("**/share/**/copyright"):
                # *_, inner_triplet, _, pkg_name, __ = copyright_path.parts
                copyright_paths.add(copyright_path)
            with open(f"{args.project}_EULA.txt", "w") as copyright_file:
                _add_licenses(copyright_file, copyright_paths, pbar)

        if args.license:
            unique_licenses = set()
            pattern = re.compile(r"AND|OR")
            for license in license_info.values():
                if "NOASSERTION" not in license:
                    splits = pattern.split(license)
                    for split in splits:
                        unique_licenses.add(re.sub("[()]", "", split.strip()))
            with open(f"{args.project}_license_info.json", "w") as license_info_file:
                json.dump(
                    {"unique": list(unique_licenses), "per_package": license_info},
                    license_info_file,
                )


if __name__ == "__main__":
    run()
