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

import os
import argparse
import logging

from vulnerability_detection import analyze_extension

BACKGROUND = 'background.js'
CONTENT_SCRIPT = 'contentscript.js'

logging.basicConfig(
    filename='doublex.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

SRC_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__)))


def analyze_directory(directory, json_apis, chrome, war, analysis_path=None):
    """
    Analyze all necessary files within a given directory.
    :param directory: Path to the directory containing extension files
    :param json_apis: Sensitive APIs to consider for the analysis
    :param chrome: Boolean to indicate Chrome-based extensions
    :param war: Boolean to indicate analysis as WAR
    :param analysis_path: Override directory for analysis results
    """
    background_page = os.path.join(directory, BACKGROUND)
    content_script = os.path.join(directory, CONTENT_SCRIPT)
    wars = os.path.join(directory, 'wars.js')
    manifest = os.path.join(directory, 'manifest.json')
    analysis_output = analysis_path or os.path.join(directory, 'analysis.json')

    if os.path.isfile(content_script):
        if not war and os.path.isfile(background_page):
            logging.info(f'Analyzing content-script and background-page in {directory}')
            analyze_extension(content_script, background_page,
                              json_analysis=analysis_output,
                              chrome=chrome, war=False,
                              json_apis=json_apis,
                              manifest_path=manifest)
        if war and os.path.isfile(wars):
            logging.info(f'Analyzing content-script and wars in {directory}')
            analyze_extension(content_script, wars,
                              json_analysis=analysis_output.replace('.json', '-war.json'),
                              chrome=chrome, war=True,
                              json_apis=json_apis,
                              manifest_path=manifest)
        logging.info(f'Analysis completed for directory: {directory}')
    else:
        logging.warning(f"Required files not found in {directory}. Skipping...")


def main():
    """ Parsing command line parameters. """

    logging.log(logging.INFO, 'Starting DoubleX')

    parser = argparse.ArgumentParser(prog='doublex',
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     description="Static analysis of a browser extension to detect "
                                                 "suspicious data flows")

    parser.add_argument("-cs", "--content-script", dest='cs', metavar="path", type=str,
                        help="path of the content script. "
                             "Default: empty/contentscript.js (i.e., empty JS file)")
    parser.add_argument("-bp", "--background-page", dest='bp', metavar="path", type=str,
                        help="path of the background page "
                             "or path of the WAR if the parameter '--war' is given. "
                             "Default for background: empty/background.js (i.e., empty JS file)")
    parser.add_argument("-dir", "--directory", dest='directory', metavar="path", type=str,
                        help="path of a directory containing the extension files. "
                             "Analyzes all supported files in the directory.")
    parser.add_argument("-dirs", "--directories", dest='directories', metavar="path", type=str,
                        help="path of a directory containing directories of extension files. "
                             "Analyzes all supported files in the directories of the given directory.")
    parser.add_argument("--war", action='store_true',
                        help="indicate that the parameter '-bp' is the path of a WAR")
    parser.add_argument("--not-chrome", dest='not_chrome', action='store_true',
                        help="indicate that the extension is not based on Chromium, e.g., for a Firefox extension")

    parser.add_argument("--manifest", metavar="path", type=str,
                        help="path of the extension manifest.json file. "
                             "Default: parent-path-of-content-script/manifest.json")
    parser.add_argument("--analysis", metavar="path", type=str,
                        help="path of the file to store the analysis results in. "
                             "Default: parent-path-of-content-script/analysis.json")
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
    directory = args.directory
    directories = args.directories

    if directory:
        logging.info(f'Analyzing extension directory: {directory}')
        analyze_directory(directory, args.apis, chrome=not args.not_chrome, war=args.war, analysis_path=args.analysis)
    elif directories:
        logging.info(f'Analyzing extension directories in: {directories}')
        for root, dirs, files in os.walk(directories):
            for d in dirs:
                analyze_directory(os.path.join(root, d), args.apis, chrome=not args.not_chrome, war=args.war,
                                  analysis_path=args.analysis)
    else:
        logging.info(f'Analyzing extension files+: {directory}')
        cs = cs or os.path.join(os.path.dirname(SRC_PATH), 'empty', CONTENT_SCRIPT)
        bp = bp or os.path.join(os.path.dirname(SRC_PATH), 'empty', BACKGROUND)
        analyze_extension(cs, bp, json_analysis=args.analysis, chrome=not args.not_chrome,
                          war=args.war, json_apis=args.apis, manifest_path=args.manifest)


if __name__ == "__main__":
    main()
