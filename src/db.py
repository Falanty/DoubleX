import argparse
import json
import logging
import os
import datetime
import re
import pandas as pd
from typing import Optional, List, Any, Dict, Union
from sqlalchemy import create_engine, text, ForeignKey, String, Integer, Boolean, Float, Engine, JSON, UniqueConstraint, \
    CursorResult
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase, relationship, Session

BP = "bp"
CS = "cs"
FILE_NAME = "file_name"
RUN = "run"
DANGER_TYPE = "danger_type"
INTERNAL_ID = "internal_id"

DANGER_TO_NESTED = {
    "direct_dangers": True,
    "indirect_dangers": True,
    "exfiltration_dangers": False
}

DB_USER = os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("POSTGRES_DB")

COMPARE_SQL = text("""
select 
    split_part(a."extension", '/', -1) as extension,
    a.war,
    ft2.name as file_type,
    d.internal_id as danger_internal_id,
    dt.name as danger_type,
    a2.name as api,
    REGEXP_REPLACE(d.value::TEXT, 'object at 0x.*>', 'object at 0x******>') AS danger_value,
    d.line as danger_line,
    split_part(d.filename, '/', -1) as danger_filename,
    d.dataflow,
    sp.internal_id as sink_param_internal_id,
    REGEXP_REPLACE(sp.value::TEXT, 'object at 0x.*>', 'object at 0x******>') AS sink_param_value,
    p.internal_id as param_internal_id,
    pd.internal_name as param_data_internal_name,
    REGEXP_REPLACE(pd.wa::TEXT, 'object at 0x.*>', 'object at 0x******>') AS param_data_wa,
    pd.line as param_data_line,
    split_part(pd.filename, '/', -1) as param_data_filename,
    REGEXP_REPLACE(pd.where::TEXT, 'object at 0x.*>', 'object at 0x******>') AS param_data_where
from run r 
left join analysis a on a.run_id = r.id 
left join benchmarks b on b.analysis_id = a.id 
left join crash c on c.benchmarks_id = b.id 
left join file_type ft on c.file_type_id = ft.id
left join file f on f.analysis_id = a.id 
left join file_type ft2 on f.file_type_id = ft2.id
left join danger d on d.file_id = f.id 
left join api a2 on d.api_id = a2.id 
left join danger_type dt on dt.id = d.danger_type_id
left join sink_param sp on sp.danger_id = d.id 
left join param p on p.danger_id = d.id 
left join param_data pd on pd.param_id = p.id
--where r."name" = 'analysis/paper_vulnerable_own'
where r.name = :run_name
order by extension, war, file_type, danger_type, danger_internal_id, sink_param_internal_id, param_internal_id, param_data_internal_name;
""")

logging.basicConfig(
    filename=f'./logs/db_{datetime.date.today()}.log',
    level=logging.DEBUG,
    format='[%(processName)s] %(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


class Base(DeclarativeBase):
    pass


class Analyst(Base):
    __tablename__ = "analyst"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=True)

    runs: Mapped[List['Run']] = relationship("Run", back_populates="analyst")


class Dataset(Base):
    __tablename__ = "dataset"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=True)

    runs: Mapped[List['Run']] = relationship("Run", back_populates="dataset")


class DoublexVersion(Base):
    __tablename__ = "doublex_version"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=True)

    runs: Mapped[List['Run']] = relationship("Run", back_populates="doublex_version")


class Run(Base):
    __tablename__ = "run"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    comment: Mapped[str] = mapped_column(String, nullable=True)
    analyst_id: Mapped[int] = mapped_column(ForeignKey("analyst.id"), nullable=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("dataset.id"), nullable=True)
    doublex_version_id: Mapped[int] = mapped_column(ForeignKey("doublex_version.id"), nullable=True)

    analyses: Mapped[List['Analysis']] = relationship("Analysis", back_populates="run")
    analyst: Mapped['Analyst'] = relationship("Analyst", back_populates="runs")
    dataset: Mapped['Dataset'] = relationship("Dataset", back_populates="runs")
    doublex_version: Mapped['DoublexVersion'] = relationship("DoublexVersion", back_populates="runs")


class Analysis(Base):
    __tablename__ = "analysis"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("run.id", ondelete="CASCADE"), nullable=False)
    extension: Mapped[str] = mapped_column(String, nullable=True)
    file_name: Mapped[str] = mapped_column(String, nullable=True)
    war: Mapped[bool] = mapped_column(Boolean, default=False)
    manifest_version: Mapped[int] = mapped_column(Integer, nullable=True)

    run: Mapped['Run'] = relationship("Run", back_populates="analyses")
    benchmarks: Mapped[Optional['Benchmarks']] = relationship("Benchmarks", back_populates="analysis")
    files: Mapped[List['File']] = relationship("File", back_populates="analysis")

    __table_args__ = (UniqueConstraint("run_id", "extension", "war", name="unique_analysis"),)


class Benchmarks(Base):
    __tablename__ = "benchmarks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analysis.id", ondelete="CASCADE"), nullable=False)

    cs_got_ast: Mapped[float] = mapped_column(Float, nullable=True)
    cs_ast: Mapped[float] = mapped_column(Float, nullable=True)
    cs_cfg: Mapped[float] = mapped_column(Float, nullable=True)
    cs_pdg: Mapped[float] = mapped_column(Float, nullable=True)
    bp_got_ast: Mapped[float] = mapped_column(Float, nullable=True)
    bp_ast: Mapped[float] = mapped_column(Float, nullable=True)
    bp_cfg: Mapped[float] = mapped_column(Float, nullable=True)
    bp_pdg: Mapped[float] = mapped_column(Float, nullable=True)
    collected_messages: Mapped[float] = mapped_column(Float, nullable=True)
    linked_messages: Mapped[float] = mapped_column(Float, nullable=True)
    cs_dangers_and_from_was: Mapped[float] = mapped_column(Float, nullable=True)
    bp_dangers_and_from_was: Mapped[float] = mapped_column(Float, nullable=True)
    cs_got_vulnerabilities: Mapped[float] = mapped_column(Float, nullable=True)
    bp_got_vulnerabilities: Mapped[float] = mapped_column(Float, nullable=True)

    analysis: Mapped['Analysis'] = relationship("Analysis", back_populates="benchmarks")
    crashes: Mapped[List['Crash']] = relationship("Crash", back_populates="benchmarks")


class Crash(Base):
    __tablename__ = "crash"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    benchmarks_id: Mapped[int] = mapped_column(ForeignKey("benchmarks.id", ondelete="CASCADE"), nullable=False)
    file_type_id: Mapped[int] = mapped_column(ForeignKey("file_type.id"), nullable=True)
    cause: Mapped[str] = mapped_column(String, nullable=True)

    file_type: Mapped['FileType'] = relationship("FileType", back_populates="crashes")
    benchmarks: Mapped['Benchmarks'] = relationship("Benchmarks", back_populates="crashes")


class FileType(Base):
    __tablename__ = "file_type"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)

    files: Mapped[List["File"]] = relationship("File", back_populates="file_type")
    crashes: Mapped[List["Crash"]] = relationship("Crash", back_populates="file_type")


class DangerType(Base):
    __tablename__ = "danger_type"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)

    dangers: Mapped[List['Danger']] = relationship("Danger", back_populates="danger_type")


class Api(Base):
    __tablename__ = "api"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)

    dangers: Mapped[List['Danger']] = relationship("Danger", back_populates="api")


class File(Base):
    __tablename__ = "file"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analysis.id", ondelete="CASCADE"), nullable=False)
    file_type_id: Mapped[int] = mapped_column(ForeignKey("file_type.id"), nullable=False)

    file_type: Mapped['FileType'] = relationship("FileType", back_populates="files")
    analysis: Mapped['Analysis'] = relationship("Analysis", back_populates="files")
    dangers: Mapped[List['Danger']] = relationship("Danger", back_populates="file")


class Danger(Base):
    __tablename__ = "danger"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_id: Mapped[int] = mapped_column(ForeignKey("file.id", ondelete="CASCADE"), nullable=False)
    danger_type_id: Mapped[int] = mapped_column(ForeignKey("danger_type.id"), nullable=False)
    api_id: Mapped[int] = mapped_column(ForeignKey("api.id"), nullable=False)
    internal_id: Mapped[str] = mapped_column(String, nullable=False)
    value: Mapped[str] = mapped_column(JSON, nullable=True)
    line: Mapped[str] = mapped_column(String, nullable=True)
    filename: Mapped[str] = mapped_column(String, nullable=True)
    dataflow: Mapped[bool] = mapped_column(Boolean, default=False)
    dangerous_dataflow: Mapped[bool] = mapped_column(Boolean, nullable=True, comment="Result after manual analysis")
    exploitable: Mapped[bool] = mapped_column(Boolean, nullable=True, comment="Result after manual analysis")
    one_way_dataflow: Mapped[bool] = mapped_column(Boolean, nullable=True, comment="Result after manual analysis")

    danger_type: Mapped['DangerType'] = relationship("DangerType", back_populates="dangers")
    api: Mapped['Api'] = relationship("Api", back_populates="dangers")
    file: Mapped['File'] = relationship("File", back_populates="dangers")
    sink_params: Mapped[List['SinkParam']] = relationship("SinkParam", back_populates="danger")
    params: Mapped[List['Param']] = relationship("Param", back_populates="danger")


class SinkParam(Base):
    __tablename__ = "sink_param"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    danger_id: Mapped[int] = mapped_column(ForeignKey("danger.id", ondelete="CASCADE"), nullable=False)
    internal_id: Mapped[str] = mapped_column(String, nullable=False)
    value: Mapped[str] = mapped_column(JSON, nullable=True)

    danger: Mapped['Danger'] = relationship("Danger", back_populates="sink_params")


class Param(Base):
    __tablename__ = "param"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    danger_id: Mapped[int] = mapped_column(ForeignKey("danger.id", ondelete="CASCADE"), nullable=False)
    internal_id: Mapped[str] = mapped_column(String, nullable=False)

    danger: Mapped['Danger'] = relationship("Danger", back_populates="params")
    param_data: Mapped['ParamData'] = relationship("ParamData", back_populates="param")


class ParamData(Base):
    __tablename__ = "param_data"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    param_id: Mapped[Optional[int]] = mapped_column(ForeignKey("param.id", ondelete="CASCADE"), nullable=True)
    internal_name: Mapped[str] = mapped_column(String, nullable=True)
    wa: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)
    line: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    filename: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    where: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    param: Mapped['Param'] = relationship("Param", back_populates="param_data")


def init_db(engine: Engine) -> None:
    Base.metadata.create_all(engine)


def parse_json_and_populate_db(session: Session, json_data: dict):
    try:
        run = session.query(Run).filter(Run.name == json_data[RUN]).first()
        if run is None:
            run_data = json_data[RUN].split('/')[-1].split('_')
            run = Run(name=json_data[RUN],
                      dataset=get_or_create(session, Dataset, Dataset.name, run_data[0]),
                      doublex_version=get_or_create(session, DoublexVersion, DoublexVersion.name, run_data[1]),
                      analyst=get_or_create(session, Analyst, Analyst.name, run_data[2]))
            session.add(run)

        analysis = Analysis(run=run,
                            extension=json_data.get("extension"),
                            file_name=json_data.get(FILE_NAME),
                            war=("war" in json_data.get(FILE_NAME)))
        session.add(analysis)

        add_benchmarks(session, analysis, json_data.get("benchmarks"))

        add_file(session, analysis, json_data, CS)
        add_file(session, analysis, json_data, BP)

        session.commit()
    except Exception as e:
        session.rollback()
        logging.exception(e)


def add_benchmarks(session: Session, analysis: Analysis, benchmarks_data: dict):
    if not benchmarks_data:
        logging.info("No benchmarks data")
        return
    benchmarks = Benchmarks(
        analysis=analysis,
        cs_got_ast=benchmarks_data.get("cs: got AST"),
        cs_ast=benchmarks_data.get("cs: AST"),
        cs_cfg=benchmarks_data.get("cs: CFG"),
        cs_pdg=benchmarks_data.get("cs: PDG"),
        bp_got_ast=benchmarks_data.get("bp: got AST"),
        bp_ast=benchmarks_data.get("bp: AST"),
        bp_cfg=benchmarks_data.get("bp: CFG"),
        bp_pdg=benchmarks_data.get("bp: PDG"),
        collected_messages=benchmarks_data.get("collected messages"),
        linked_messages=benchmarks_data.get("linked messages"),
        cs_dangers_and_from_was=benchmarks_data.get("cs: dangers & from WA"),
        bp_dangers_and_from_was=benchmarks_data.get("bp: dangers & from WA"),
        cs_got_vulnerabilities=benchmarks_data.get("cs: got vulnerabilities"),
        bp_got_vulnerabilities=benchmarks_data.get("bp: got vulnerabilities")
    )
    session.add(benchmarks)

    crash_data = benchmarks_data.get("crashes")
    if crash_data:
        add_crashes(session, benchmarks, crash_data)


def add_crashes(session: Session, benchmarks: Benchmarks, crashes: list):
    for crash_data in crashes:
        crash = Crash(cause=crash_data, benchmarks=benchmarks)

        file_type_match = re.search(fr'^({BP}|{CS}):', crash_data)
        if file_type_match:
            crash.file_type = get_or_create(session, FileType, FileType.name, file_type_match.group(1))
        session.add(crash)


def add_file(session: Session, analysis: Analysis, json_data: dict, file_type: str):
    file_data = json_data.get(file_type)
    if not file_data:
        logging.info(f"No data for file: {file_type}")
        return
    file = File(analysis=analysis)
    file_type = get_or_create(session, FileType, FileType.name, file_type)
    file.file_type = file_type
    session.add(file)
    for danger_type, nested in DANGER_TO_NESTED.items():
        for internal_id, danger in file_data.get(danger_type).items():
            danger[DANGER_TYPE] = danger_type
            danger[INTERNAL_ID] = internal_id
            add_danger(session, file, danger, nested=nested)


def add_danger(session: Session, file: File, danger: dict, nested: bool):
    params, sink_params = extract_params(danger, nested)
    danger = Danger(file=file,
                    danger_type=get_or_create(session, DangerType, DangerType.name, danger.get(DANGER_TYPE)),
                    api=get_or_create(session, Api, Api.name, danger.get("danger")),
                    value=danger.get("value"),
                    line=danger.get("line"),
                    filename=danger.get("filename"),
                    dataflow=danger.get("dataflow"),
                    internal_id=danger.get(INTERNAL_ID),
                    sink_params=sink_params,
                    params=params)
    session.add(danger)


def extract_params(danger: dict, nested: bool):
    sink_params = []
    params = []

    def _create_param_object(name, values):
        param_data = ParamData(internal_name=name,
                               wa=values.get("wa"),
                               line=values.get("line"),
                               filename=values.get("filename"),
                               where=values.get("where"))
        return Param(internal_id=name, param_data=param_data)

    for key, value in danger.items():

        if nested and key.startswith("param_id"):
            for param_key, param_values in value.items():
                param = _create_param_object(param_key, param_values)
                param.internal_id = key
                params.append(param)

        elif not nested and key.startswith("sent_to_wa"):
            param = _create_param_object(key, value)
            params.append(param)

        if key.startswith("sink-param"):
            sink_params.append(SinkParam(internal_id=key, value=value))
    return params, sink_params


def parse_sink_params(danger: dict):
    sink_params = []
    for key, value in danger.items():
        if not key.startswith("sink-param"):
            continue
        sink_params.append(SinkParam(internal_id=key, value=value))
    return sink_params


def get_or_create(session: Session, model_class: Any, field: Mapped[Any], value: Any):
    if not hasattr(session, "lookup_cache"):
        session.lookup_cache = {}

    cache_key = (model_class, field.key, value)
    if cache_key in session.lookup_cache:
        return session.lookup_cache[cache_key]

    instance = session.query(model_class).filter(field == value).first()
    if instance is None:
        param_map = {field.key: value}
        instance = model_class(**param_map)
        session.add(instance)

    session.lookup_cache[cache_key] = instance
    return instance


def calculate_evo_numbers(extension_list, api_list, target_file: str):
    logging.info("Calculating extension evolutions")

    # Step 1: Build the evolutions dictionary
    evolutions = build_evolutions_dict(extension_list, api_list)

    # Step 2: Filter extensions with at least one dataflow
    filtered_evolutions = filter_evolutions_with_dataflow(evolutions)

    # Step 3: Transform evolutions to calculate differences in version changes
    transformed_evolutions = transform_evolutions(filtered_evolutions)

    # Step 4: Calculate dataflow changes
    dataflow_changes = calculate_dataflow_changes(transformed_evolutions)

    # Step 5: Write results to target file
    logging.info(f"Dataflow changes: {dataflow_changes}")
    write_json_to_file(dataflow_changes, target_file)


def build_evolutions_dict(extension_danger_list, api_list) -> Dict[str, Any]:
    """
    Build the evolutions dictionary from the extension list.

    Returns:
        A dictionary of the following format:

        {
            extension_name_1: {
                extension_version_1: {
                    file_type_1: {
                        api_1: 0,
                        api_2: 0,
                    },
                    file_type_2: {
                        api_1: 0,
                        api_2: 1,
                    },
                    file_type_1-war: {
                        api_1: 5,
                        api_2: 1,
                    }
                    file_type_2-war: {
                        api_1: 2,
                        api_2: 3,
                    }
                },
                extension_name_2: {
                    file_type_1: {
                        api_1: 3,
                        api_2: 2,
                    }
                }
            }
        }
    """
    evolutions = {}
    apis = list(api_list.mappings().fetchall())

    for danger in extension_danger_list.mappings():
        extension_name = danger["extension_name_without_version"]
        extension_api = danger["api"]
        extension_version = danger["extension"]
        file_type = danger["file_type"]
        dataflow = danger["dataflow"]

        # Initialize nested dictionary levels as needed
        evolutions.setdefault(extension_name, {})
        evolutions[extension_name].setdefault(extension_version, {})
        evolutions[extension_name][extension_version].setdefault(file_type, {})
        for api in apis:
            evolutions[extension_name][extension_version][file_type].setdefault(api["name"], 0)

        if extension_api is None:
            continue

        # Increment dataflow count
        if dataflow:
            evolutions[extension_name][extension_version][file_type][extension_api] += 1

    logging.debug(f"Evolutions pre filter: {len(evolutions)}")
    return evolutions


def filter_evolutions_with_dataflow(evolutions: Dict[str, Any]) -> Dict[str, Any]:
    """Filter evolutions to include only those with at least one dataflow."""
    filtered_evolutions = {}

    for extension, version_dict in evolutions.items():
        dataflow_for_extension = sum(
            count
            for file_types in version_dict.values()
            for apis in file_types.values()
            for count in apis.values()
        )
        if dataflow_for_extension > 0:
            filtered_evolutions[extension] = version_dict

    logging.debug(f"Evolutions post filter: {len(filtered_evolutions)}")
    return filtered_evolutions


def transform_evolutions(new_evolutions: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform the new evolutions format into the expected format for calculate_dataflow_changes.

    Args:
        new_evolutions: A dictionary containing extension evolution data in the new format.

    Returns:
        Transformed data in the expected format.
    """
    transformed_data = {}

    for extension_name, extension_versions in new_evolutions.items():
        transformed_data[extension_name] = {}

        for version, file_types in extension_versions.items():
            for file_type, apis in file_types.items():
                for api, count in apis.items():
                    # Ensure that the api exists in the transformed data
                    if api not in transformed_data[extension_name]:
                        transformed_data[extension_name][api] = {}

                    # Ensure that the file_type exists in the current api
                    if file_type not in transformed_data[extension_name][api]:
                        transformed_data[extension_name][api][file_type] = {}

                    # Transform the version and count into the expected format
                    transformed_data[extension_name][api][file_type][version] = count

    return transformed_data


def calculate_dataflow_changes(evolutions: Dict[str, Any]) -> dict[str, Union[dict[str, int], dict[str, int]]]:
    """
    Calculate the changes in dataflow based on evolutions.

    Args:
        evolutions: A dictionary containing filtered extension evolution data.

    Returns:
        A dictionary summarizing the counts of added, removed, mixed, and unchanged changes in dataflow.
    """
    dataflow_changes = {
        "all_changes": {
            "added": 0,
            "removed": 0,
        },
        "apis": {},
        "extensions": {},
        "compiled": {
            "extensions": {
                "added": 0,
                "removed": 0,
                "mixed": 0,
                "unchanged": 0
            },
        }
    }

    for extension, api_dicts in evolutions.items():
        dataflow_changes["extensions"][extension] = {
            "added": 0,
            "removed": 0
        }
        for api, file_types in api_dicts.items():
            if api not in dataflow_changes["apis"]:
                dataflow_changes["apis"][api] = {}

            for file_type, versions in file_types.items():
                if file_type not in dataflow_changes["apis"][api]:
                    dataflow_changes["apis"][api][file_type] = {
                        "added": 0,
                        "removed": 0
                    }
                logging.debug(f"Calculating dataflow for extension: {extension} - {api} - {file_type}")
                added_count, removed_count = analyze_version_changes(versions)
                dataflow_changes["all_changes"]["added"] += added_count
                dataflow_changes["all_changes"]["removed"] += removed_count
                dataflow_changes["extensions"][extension]["added"] += added_count
                dataflow_changes["extensions"][extension]["removed"] += removed_count
                dataflow_changes["apis"][api][file_type]["added"] += added_count
                dataflow_changes["apis"][api][file_type]["removed"] += removed_count
    logging.debug(dataflow_changes["extensions"])
    for extension_data in dataflow_changes["extensions"].values():
        calculate_mixed_unchanged(dataflow_changes["compiled"]["extensions"], extension_data)
    return dataflow_changes


def calculate_mixed_unchanged(dataflow_changes, extension_data):
    if extension_data["added"] and extension_data["removed"]:
        dataflow_changes["mixed"] += 1
    elif extension_data["added"]:
        dataflow_changes["added"] += 1
    elif extension_data["removed"]:
        dataflow_changes["removed"] += 1
    else:
        dataflow_changes["unchanged"] += 1


def analyze_version_changes(versions: Dict[str, int]) -> (int, int):
    """
    Analyze changes between versions and determine if counts of dataflow increased or decreased.

    Args:
        versions: A dictionary where keys are version strings, and values are their counts.

    Returns:
        A tuple:
        - added (int): number of increases in counts between versions.
        - removed (int): number of decreases in counts between versions.
    """
    added = 0
    removed = 0
    # Get an iterator of version counts
    version_to_counts = iter(versions.items())
    prev_version, prev_count = next(version_to_counts, None)

    for version, count in version_to_counts:
        logging.debug(f"Analyzing version changes: {prev_version} - {version}")
        logging.debug(f"Counts: {prev_count} - {count}")
        if count > prev_count:
            added += 1
        elif count < prev_count:
            removed += 1
        prev_version, prev_count = version, count

    logging.debug(f"added: {added} - removed: {removed}")
    return added, removed


def write_json_to_file(data: Any, file_path: str):
    """Write the given data to a JSON file."""
    with open(file_path, "w") as f:
        json.dump(data, f)


def main():
    """ Parsing command line parameters. """

    parser = argparse.ArgumentParser(prog="db",
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     description="DB management."
                                                 "Used to initialize database, "
                                                 "save json analysis date or extract json data.")

    parser.add_argument("-s", "--source", dest="s", metavar="path", type=str,
                        help="path of the dir containing analysis files. "
                             "mutually exclusive with '-s'")
    parser.add_argument("-d", "--destination", dest="d", metavar="path", type=str,
                        help="path of the dir to store the exported json files. "
                             "mutually exclusive with '-d'")
    parser.add_argument("-i", "--init", dest="i", action="store_true",
                        help="initializes the database. "
                             "if the database was already initialized, this has no effect")
    parser.add_argument("-c", "--compare", dest="c", metavar=("run1", "run2"), nargs=2, type=str,
                        help="compares two runs and saves the result as a csv file. "
                             "the name of the file is <run1>-<run2>-diff.csv.")
    parser.add_argument("-ec", "--evolutions-calc", dest="ec", type=str,
                        help="compares version of extensions and calculates evolution differences. "
                             "The result is stored in a specified json file.")
    parser.add_argument("-cd", "--compare-destination", dest="cd", metavar="path", type=str,
                        help="path of the dir to store the comparison csv file. "
                             "only valid in combination with '-c'")

    args = parser.parse_args()
    source = args.s
    destination = args.s
    init = args.i
    compare = args.c
    compare_destination = args.cd
    evolutions_calc = args.ec

    engine = create_engine(f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}")
    with engine.connect() as conn:
        try:
            conn.execute(text("SELECT 'hello world'"))
        except Exception as e:
            logging.exception(f"Error establishing connection to db: {e}")

    if init:
        init_db(engine)

    if source and os.path.isdir(source):
        logging.info(f'Loading data to db from: {source}')
        with Session(engine).no_autoflush as session:
            for root, dirs, files in os.walk(source):
                for i, file in enumerate(files):
                    if not file.endswith(".json"):
                        logging.info(f"Skipping non-json file: {file}")
                        continue
                    json_data = json.load(open(os.path.join(root, file), 'r'))
                    json_data[RUN] = root
                    json_data[FILE_NAME] = file

                    logging.info(f"Saving file {i+1}/{len(files)} to db: {json_data.get(FILE_NAME)}")
                    parse_json_and_populate_db(session, json_data)
        return

    if destination and os.path.isdir(destination):
        logging.info(f'Extracting data from db to: {destination}')

    if compare and len(compare) == 2:
        run1, run2 = compare
        logging.info(f'Comparing data of runs: {run1} - {run2}')
        runs = dict()
        with engine.connect() as conn:
            for run in compare:
                runs[run] = pd.read_sql(COMPARE_SQL, conn, params={"run_name": run})
        diff = runs[run1].compare(runs[run2])

        file_path = f"{run1.replace('/', '_')}--{run2.replace('/', '_')}--diff.csv"
        if compare_destination:
            file_path = f"{compare_destination}/{file_path}"
        logging.info(f"Saving comparison diff to {file_path}")
        diff.to_csv(path_or_buf=file_path, index=True)

    if evolutions_calc:
        with engine.connect() as conn:
            try:
                codex_data = conn.execute(text("""
                    SELECT * 
                    FROM codex_espree_patrick_extensions_dataflow 
                    ORDER BY extension_name_without_version, string_to_array(split_part(extension, '.', -1), '_')::int[]
                """))
                api_data = conn.execute(text("""
                    SELECT * 
                    FROM api
                    ORDER BY name
                """))
                calculate_evo_numbers(codex_data, api_data, evolutions_calc)
            except Exception as e:
                logging.exception(f"Could not retrieve data: {e}")


if __name__ == "__main__":
    main()
