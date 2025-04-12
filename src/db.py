import argparse
import logging
import os
from typing import Optional, List
from sqlalchemy import create_engine, text, ForeignKey, String, Integer, Boolean, Float
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase, relationship

DB_USER = os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("POSTGRES_DB")

engine = create_engine(f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}")

with engine.connect() as conn:
    try:
        conn.execute(text("SELECT 'hello world'"))
    except Exception as e:
        logging.exception(f"Error establishing connection to db: {e}")


logging.basicConfig(
    filename=f'./logs/unpack_{datetime.date.today()}.log',
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
    benchmarks_id: Mapped[int] = mapped_column(ForeignKey("benchmarks.id"), nullable=True)
    extension: Mapped[str] = mapped_column(String, nullable=True)
    fullname: Mapped[str] = mapped_column(String, nullable=True)
    war: Mapped[bool] = mapped_column(Boolean, default=False)

    run: Mapped['Run'] = relationship("Run", back_populates="analyses")
    benchmarks: Mapped[Optional['Benchmarks']] = relationship("Benchmarks")


class Benchmarks(Base):
    __tablename__ = "benchmarks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analysis.id"), nullable=False)

    crash_cs: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    crash_bp: Mapped[Optional[str]] = mapped_column(String, nullable=True)
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


class FileType(Base):
    __tablename__ = "file_type"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String, nullable=False)


class DangerType(Base):
    __tablename__ = "danger_type"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String, nullable=False)


class File(Base):
    __tablename__ = "file"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analysis.id"), nullable=False)
    file_type_id: Mapped[int] = mapped_column(ForeignKey("file_type.id"), nullable=False)


class Api(Base):
    __tablename__ = "api"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_type_id: Mapped[int] = mapped_column(ForeignKey("file_type.id"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)


class Danger(Base):
    __tablename__ = "danger"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_id: Mapped[int] = mapped_column(ForeignKey("file.id"), nullable=False)
    danger_type_id: Mapped[int] = mapped_column(ForeignKey("danger_type.id"), nullable=False)
    api_id: Mapped[int] = mapped_column(ForeignKey("api.id"), nullable=False)
    internal_id: Mapped[int] = mapped_column(Integer, nullable=False)
    value: Mapped[str] = mapped_column(String, nullable=True)
    line: Mapped[int] = mapped_column(Integer, nullable=True)
    filename: Mapped[str] = mapped_column(String, nullable=True)
    dataflow: Mapped[bool] = mapped_column(Boolean, default=False)


class SinkParam(Base):
    __tablename__ = "sink_param"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    danger_id: Mapped[int] = mapped_column(ForeignKey("danger.id"), nullable=False)
    internal_id: Mapped[int] = mapped_column(Integer, nullable=False)
    value: Mapped[str] = mapped_column(String, nullable=True)


class Param(Base):
    __tablename__ = "param"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    danger_id: Mapped[int] = mapped_column(ForeignKey("danger.id"), nullable=False)
    internal_id: Mapped[int] = mapped_column(Integer, nullable=False)


class ParamData(Base):
    __tablename__ = "param_data"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    danger_id: Mapped[int] = mapped_column(ForeignKey("danger.id"), nullable=False)
    param_id: Mapped[Optional[int]] = mapped_column(ForeignKey("param.id"), nullable=True)
    internal_id: Mapped[int] = mapped_column(Integer, nullable=False)
    internal_name: Mapped[str] = mapped_column(String, nullable=False)
    wa: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    line: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    filename: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    where: Mapped[Optional[str]] = mapped_column(String, nullable=True)


def init_db():
    Base.metadata.create_all(engine)


def main():
    """ Parsing command line parameters. """

    parser = argparse.ArgumentParser(prog="unpack",
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     description="DB management."
                                                 "Used to initialize database, "
                                                 "save json analysis date or extract json data.")

    parser.add_argument("-s", "--source", dest="s", metavar="path", type=str,
                        required=True, help="path of the dir containing analysis files. "
                                            "mutually exclusive with '-s'")
    parser.add_argument("-d", "--destination", dest="d", metavar="path", type=str,
                        help="path of the dir to store the exported json files. "
                             "mutually exclusive with '-d'")
    parser.add_argument("-i", "--init", dest="i", action="store_true",
                        help="initializes the database."
                             "if the database was already initialized, this has no effect")

    args = parser.parse_args()
    source = args.s
    destination = args.s
    init = args.i

    if init:
        init_db()

    if os.path.isdir(source):
        logging.info(f'Loading data to db from: {source}')
        return
    if os.path.isdir(destination):
        logging.info(f'Extracting data from db to: {destination}')
        return
    logging.info()


if __name__ == "__main__":
    main()
