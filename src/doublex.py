# Copyright (C) 2021 Aurore Fass
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


"""
    To call DoubleX from the command-line.
"""
import datetime
import os
import argparse
import logging
from multiprocessing import Process, Queue

from vulnerability_detection import analyze_extension

BACKGROUND = 'background.js'
CONTENT_SCRIPT = 'content_scripts.js'

logging.basicConfig(
    filename=f'./logs/{datetime.date.today()}.log',
    level=logging.CRITICAL,
    format='[%(processName)s] %(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

SRC_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__)))


def producer(dir_queue: Queue, root, dirs):
    for d in dirs:
        dir_queue.put(os.path.join(root, d))
    dir_queue.put(None)


def consumer(dir_queue: Queue, args):
    while True:
        logging.critical(f'Current directories in queue: {dir_queue.qsize()}')
        directory = dir_queue.get()
        if directory is None:
            logging.critical(f'Exiting directory queue...')
            dir_queue.put(None)
            break
        logging.critical(f'Started analyzing directory: {directory}')
        analyze_directory(directory, args)
        logging.critical(f'Finished analyzing directory: {directory}')


def analyze_directory(directory, args):
    """
    Analyze all necessary files within a given directory.
    :param directory: Path to the directory containing extension files
    :param args: Arguments from the command line
    """
    background_page = os.path.join(directory, BACKGROUND)
    content_script = os.path.join(directory, CONTENT_SCRIPT)
    wars = os.path.join(directory, 'wars.js')
    manifest = os.path.join(directory, 'manifest.json')
    if args.analysis_dir:
        analysis_dir = args.analysis_dir
        analysis_file = f'{os.path.basename(directory)}-{args.analysis}'
    else:
        analysis_dir = directory
        analysis_file = args.analysis
    analysis_path = os.path.join(analysis_dir, analysis_file)

    if os.path.isfile(analysis_path) and args.skip_existing:
        logging.critical(f"Skipping analysis for: {directory} - analysis files exist already")
        return

    if os.path.isfile(content_script):
        if os.path.isfile(background_page):
            logging.critical(f'Analyzing content-script and background-page in {directory}')
            analyze_extension(content_script, background_page,
                              json_analysis=analysis_path,
                              chrome=not args.not_chrome,
                              war=args.war,
                              json_apis=args.apis,
                              manifest_path=manifest)
        if os.path.isfile(wars):
            logging.critical(f'Analyzing content-script and wars in {directory}')
            analyze_extension(content_script, wars,
                              json_analysis=analysis_path.replace('.json', '-war.json'),
                              chrome=not args.not_chrome,
                              war=args.war,
                              json_apis=args.apis,
                              manifest_path=manifest)
        logging.critical(f'Analysis completed for directory: {directory}')
    else:
        logging.warning(f"Required files not found in {directory}. Skipping...")


def main():
    """ Parsing command line parameters. """

    logging.critical('Starting DoubleX')

    parser = argparse.ArgumentParser(prog='doublex',
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     description="Static analysis of a browser extension to detect "
                                                 "suspicious data flows")

    parser.add_argument("-cs", "--content-script", dest='cs', metavar="path", type=str,
                        help="path of the content script. "
                             "Default: empty/content_scripts.js (i.e., empty JS file)")
    parser.add_argument("-bp", "--background-page", dest='bp', metavar="path", type=str,
                        help="path of the background page "
                             "or path of the WAR if the parameter '--war' is given. "
                             "Default for background: empty/background.js (i.e., empty JS file)")
    parser.add_argument("-dir", "--directory", dest='dir', metavar="path", type=str,
                        help="path of a directory containing the extension files. "
                             "Analyzes all supported files in the directory."
                             "This argument is mutually exclusive with '-dirs'"
                             "This argument overrides '-cs' and '-bp' and '--war'")
    parser.add_argument("-dirs", "--directories", dest='dirs', metavar="path", type=str,
                        help="path of a directory containing directories of extension files. "
                             "Analyzes all supported files in the directories of the given directory. "
                             "This argument is mutually exclusive with '-dir'."
                             "This argument overrides '-cs', '-bp' and '--war'")
    parser.add_argument("-pc", "--process-count", dest='pc', metavar="int", type=int,
                        default=1, choices=range(1, 201),
                        help="the number of processes to use for the analysis. "
                             "Default: 1 "
                             "Maximum: 200 "
                             "This argument is only used in combination with '-dirs'")
    parser.add_argument("--war", action='store_true',
                        help="indicate that the parameter '-bp' is the path of a WAR")
    parser.add_argument("--not-chrome", dest='not_chrome', action='store_true',
                        help="indicate that the extension is not based on Chromium, e.g., for a Firefox extension")

    parser.add_argument("--manifest", metavar="path", type=str,
                        help="path of the extension manifest.json file. "
                             "Default: parent-path-of-content-script/manifest.json")
    parser.add_argument("--analysis", metavar="path", type=str,
                        default="analysis.json",
                        help="path of the file to store the analysis results in. "
                             "Default: parent-path-of-content-script/analysis[-war].json")
    parser.add_argument("-ad", "--analysis-dir", dest="analysis_dir", metavar="path", type=str,
                        help="path of the directory to store the analysis file(s) in. "
                             "The files will be named '<extension-dir>-analysis.json' "
                             "This argument is only used in combination with '-dir' or '-dirs'")
    parser.add_argument("-skip", "--skip-existing", dest="skip_existing", action="store_true",
                        help="Skips the analysis for extensions if an analysis file exists already."
                             "This argument is only used in combination with '-dir' or '-dirs'")
    parser.add_argument("--apis", metavar="str", type=str, default='permissions',
                        help='''specify the sensitive APIs to consider for the analysis:
    - 'permissions' (default): DoubleX selected APIs iff the extension has the corresponding permissions;
    - 'all': DoubleX selected APIs irrespective of the extension permissions;
    - 'empoweb': APIs from the EmPoWeb paper; to use ONLY on the EmPoWeb ground-truth dataset;
    - path: APIs listed in the corresponding json file; a template can be found in src/suspicious_apis/README.md.''')

    # TODO: control verbosity of logging?

    args = parser.parse_args()

    cs = args.cs
    bp = args.bp
    directory = args.dir
    directories = args.dirs
    process_count = args.pc

    if args.analysis_dir and not os.path.isdir(args.analysis_dir):
        os.makedirs(args.analysis_dir)

    if directory:
        logging.critical(f'Analyzing extension directory: {directory}')
        analyze_directory(directory, args)
    elif directories:
        dir_queue = Queue()
        logging.critical(f'Analyzing extension directories in: {directories}')
        dirs = os.listdir(directories)
        logging.critical(f'Starting producer process...')
        input_process = Process(target=producer, args=(dir_queue, directories, dirs))
        input_process.start()

        logging.critical(f'Starting {process_count} consumer processes...')
        analysis_processes = [Process(target=consumer, args=[dir_queue, args],
                                      name=f'AnalysisProcess-{process_id}') for process_id in range(process_count)]
        for process in analysis_processes:
            process.start()
        all_processes = analysis_processes + [input_process]
        for process in all_processes:
            process.join()

    else:
        logging.critical(f'Analyzing extension files: {directory}')
        cs = cs or os.path.join(os.path.dirname(SRC_PATH), 'empty', CONTENT_SCRIPT)
        bp = bp or os.path.join(os.path.dirname(SRC_PATH), 'empty', BACKGROUND)
        analyze_extension(cs, bp, json_analysis=args.analysis, chrome=not args.not_chrome,
                          war=args.war, json_apis=args.apis, manifest_path=args.manifest)

    logging.critical('DoubleX finished')


if __name__ == "__main__":
    main()
