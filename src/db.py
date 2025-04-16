import argparse
import json
import logging
import os
import datetime
from typing import Optional, List
from sqlalchemy import create_engine, text, ForeignKey, String, Integer, Boolean, Float, Engine, JSON
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

logging.basicConfig(
    filename=f'./logs/db_{datetime.date.today()}.log',
    level=logging.DEBUG,
    format='[%(processName)s] %(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


class Base(DeclarativeBase):
    pass


class Run(Base):
    __tablename__ = "run"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)

    analyses: Mapped[List['Analysis']] = relationship("Analysis", back_populates="run")


class Analysis(Base):
    __tablename__ = "analysis"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("run.id"), nullable=False)
    extension: Mapped[str] = mapped_column(String, nullable=True)
    file_name: Mapped[str] = mapped_column(String, nullable=True)
    war: Mapped[bool] = mapped_column(Boolean, default=False)

    run: Mapped['Run'] = relationship("Run", back_populates="analyses")
    benchmarks: Mapped[Optional['Benchmarks']] = relationship("Benchmarks", back_populates="analysis")
    files: Mapped[List['File']] = relationship("File", back_populates="analysis")


class Benchmarks(Base):
    __tablename__ = "benchmarks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analysis.id"), nullable=False)

    crashes: Mapped[Optional[str]] = mapped_column(String, nullable=True)
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


class FileType(Base):
    __tablename__ = "file_type"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)

    file: Mapped[List["File"]] = relationship("File", back_populates="file_type")


class DangerType(Base):
    __tablename__ = "danger_type"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)

    danger: Mapped[List['Danger']] = relationship("Danger", back_populates="danger_type")


class Api(Base):
    __tablename__ = "api"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)

    danger: Mapped[List['Danger']] = relationship("Danger", back_populates="api")


class File(Base):
    __tablename__ = "file"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analysis.id"), nullable=False)
    file_type_id: Mapped[int] = mapped_column(ForeignKey("file_type.id"), nullable=False)

    file_type: Mapped['FileType'] = relationship("FileType", back_populates="file")
    analysis: Mapped['Analysis'] = relationship("Analysis", back_populates="files")
    dangers: Mapped[List['Danger']] = relationship("Danger", back_populates="file")


class Danger(Base):
    __tablename__ = "danger"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_id: Mapped[int] = mapped_column(ForeignKey("file.id"), nullable=False)
    danger_type_id: Mapped[int] = mapped_column(ForeignKey("danger_type.id"), nullable=False)
    api_id: Mapped[int] = mapped_column(ForeignKey("api.id"), nullable=False)
    internal_id: Mapped[str] = mapped_column(String, nullable=False)
    value: Mapped[str] = mapped_column(String, nullable=True)
    line: Mapped[str] = mapped_column(String, nullable=True)
    filename: Mapped[str] = mapped_column(String, nullable=True)
    dataflow: Mapped[bool] = mapped_column(Boolean, default=False)

    danger_type: Mapped['DangerType'] = relationship("DangerType", back_populates="danger")
    api: Mapped['Api'] = relationship("Api", back_populates="danger")
    file: Mapped['File'] = relationship("File", back_populates="dangers")
    sink_params: Mapped[List['SinkParam']] = relationship("SinkParam", back_populates="danger")
    params: Mapped[List['Param']] = relationship("Param", back_populates="danger")


class SinkParam(Base):
    __tablename__ = "sink_param"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    danger_id: Mapped[int] = mapped_column(ForeignKey("danger.id"), nullable=False)
    internal_id: Mapped[str] = mapped_column(String, nullable=False)
    value: Mapped[str] = mapped_column(JSON, nullable=True)

    danger: Mapped['Danger'] = relationship("Danger", back_populates="sink_params")


class Param(Base):
    __tablename__ = "param"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    danger_id: Mapped[int] = mapped_column(ForeignKey("danger.id"), nullable=False)
    internal_id: Mapped[str] = mapped_column(String, nullable=False)

    danger: Mapped['Danger'] = relationship("Danger", back_populates="params")
    param_data: Mapped['ParamData'] = relationship("ParamData", back_populates="param")


class ParamData(Base):
    __tablename__ = "param_data"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    param_id: Mapped[Optional[int]] = mapped_column(ForeignKey("param.id"), nullable=True)
    internal_name: Mapped[str] = mapped_column(String, nullable=True)
    wa: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)
    line: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    filename: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    where: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    param: Mapped['Param'] = relationship("Param", back_populates="param_data")


def init_db(engine: Engine) -> None:
    Base.metadata.create_all(engine)


def parse_json_and_populate_db(session: Session, json_data: dict):
    logging.info(f"Saving to db: {json_data.get(FILE_NAME)}")
    try:
        extension = json_data.get("extension")
        benchmarks_data = json_data.get("benchmarks")

        run = get_or_create(session, Run, Run.name, json_data[RUN])

        analysis = Analysis(run=run,
                            extension=extension,
                            file_name=json_data.get(FILE_NAME),
                            war=("war" in json_data.get(FILE_NAME)))
        session.add(analysis)

        if benchmarks_data:
            benchmarks = Benchmarks(
                analysis=analysis,
                crashes=", ".join(benchmarks_data.get("crashes")),
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

        add_file(session, analysis, json_data, CS)
        add_file(session, analysis, json_data, BP)
        session.commit()

    except Exception as e:
        session.rollback()
        logging.exception(e)


def add_file(session: Session, analysis: Analysis, json_data: dict, file_type: str):
    file_data = json_data.get(file_type)
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


def parse_sink_params(danger):
    sink_params = []
    for key, value in danger.items():
        if not key.startswith("sink-param"):
            continue
        sink_params.append(SinkParam(internal_id=key, value=value))
    return sink_params


def get_or_create(session, model_class, field, value):
    instance = session.query(model_class).filter(field == value).first()
    if instance is None:
        param_map = {field.key: value}
        instance = model_class(**param_map)
        session.add(instance)
    return instance


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

    args = parser.parse_args()
    source = args.s
    destination = args.s
    init = args.i

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
                for file in files:
                    if not file.endswith(".json"):
                        continue
                    json_data = json.load(open(os.path.join(root, file), 'r'))
                    json_data[RUN] = root
                    json_data[FILE_NAME] = file
                    parse_json_and_populate_db(session, json_data)
        return

    if destination and os.path.isdir(destination):
        logging.info(f'Extracting data from db to: {destination}')


if __name__ == "__main__":
    main()
