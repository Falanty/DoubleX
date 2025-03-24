# Copyright (C) 2021 Aurore Fass and Ben Stock
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
    Unpacking a Chrome extension and extracting the different components.
"""

import os
import json
import logging
import fnmatch
import hashlib
import argparse
import time
import datetime
from typing import Callable
from urllib.parse import urljoin
from zipfile import ZipFile
from bs4 import BeautifulSoup
from multiprocessing import Process, Queue, Value

logging.basicConfig(
    filename=f'./logs/unpack_{datetime.date.today()}.log',
    level=logging.DEBUG,
    format='[%(processName)s] %(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def benchmark(func: Callable):
    def wrapper(*args, benchmark=False, **kwargs):
        if benchmark:
            start = time.perf_counter()
            result = func(*args, **kwargs)
            end = time.perf_counter()
            duration = end - start
            logging.debug(f"Execution time for {func.__name__}: {duration} seconds")
        else:
            result = func(*args, **kwargs)
        return result

    return wrapper


def read_from_zip(zf, filename):
    """ Returns the bytes of the file filename in the archive zf. """

    filename = filename.lstrip("./").split("?")[0]

    try:
        return zf.read(filename)

    except KeyError:
        # Now try lowercase
        mapping = {}
        for zi in zf.infolist():
            mapping[zi.filename.lower()] = zi.filename
        if filename.lower() in mapping:
            return zf.read(mapping[filename.lower()])
        logging.exception(zf.filename, filename, 'KeyError')
        return b''

    except Exception as e:
        logging.exception(zf.filename, filename, e)
        return b''


def beautify_script(content, suffix):
    """ Beautifies a script with js-beautify (https://www.npmjs.com/package/js-beautify). """

    filehash = hashlib.md5(content.encode()).hexdigest()
    temp_file = "/tmp/%s_%s" % (filehash, suffix.replace("/", "_"))

    with open(temp_file, "w") as fh:
        fh.write(content)
    os.system("js-beautify -t -r %s > /dev/null" % temp_file)

    with open(temp_file, "r") as fh:
        content = fh.read()
    os.unlink(temp_file)

    return content


def pack_and_beautify(extension_zip, scripts):
    """ Appends and beautifies the content of scripts. """

    all_content = ""

    for script in scripts:
        if "jquery" in script.lower() or \
                not script.endswith(".js") or \
                script.startswith("https://") \
                or script.startswith("https://") or \
                "jq.min.js" in script.lower() or \
                "jq.js" in script.lower():
            continue

        content = read_from_zip(extension_zip, script)
        if len(content):
            pass
        else:
            continue
        all_content += "// New file: %s\n" % script
        content = content.replace(b"use strict", b"")
        content = content.replace(b"...", b"")
        all_content += beautify_script(content.decode("utf8", "ignore"), extension_zip.filename) + "\n"

    return all_content


def get_all_content_scripts(manifest, extension_zip):
    """ Extracts the content scripts. """

    content_scripts = manifest.get("content_scripts", [])

    all_scripts = list()
    for entry in content_scripts:
        if not isinstance(entry, dict):
            continue
        for script in entry.get("js", []):
            if script not in all_scripts:
                all_scripts.append(script)

    return pack_and_beautify(extension_zip, all_scripts)


def get_all_background_scripts_v2(manifest, extension_zip):
    """ Extracts the background scripts if manifest version 2. """

    background = manifest.get("background")

    if not background or not isinstance(background, dict):
        return ""

    all_scripts = list()
    inline_scripts = ""

    for script in background.get("scripts", []):  # Background scripts
        if not isinstance(script, str):
            continue
        if script not in all_scripts:
            all_scripts.append(script)

    page = background.get("page")  # Background page
    if page:
        content = read_from_zip(extension_zip, page.split("?")[0].split("#")[0])
        soup = BeautifulSoup(content, features="html.parser")
        for script in soup.find_all("script"):
            if "src" in script.attrs:
                src_path = urljoin(page, script["src"])
                if src_path not in all_scripts:
                    all_scripts.append(src_path)
            elif script.string:
                inline_scripts += "// New inline (from %s)\n" % background
                inline_scripts += beautify_script(script.string, extension_zip.filename) + "\n"

    return pack_and_beautify(extension_zip, all_scripts)


def get_all_background_scripts_v3(manifest, extension_zip):
    """ Extracts the background scripts if manifest version 3. """

    background = manifest.get("background")

    if not background or not isinstance(background, dict):
        return ""

    all_scripts = list()
    script = background.get("service_worker", -1)
    if isinstance(script, str):
        if script not in all_scripts:
            all_scripts.append(script)

    return pack_and_beautify(extension_zip, all_scripts)


def get_wars_v2(manifest, extension_zip):
    """ Extracts the web accessible resources if manifest version 2. """

    all_scripts = set()
    war_scripts = ""

    if "web_accessible_resources" in manifest:
        try:
            background_page = manifest.get("background", {}).get("page")
        except AttributeError:
            background_page = None
        for contained_file in extension_zip.namelist():
            for whitelisted in manifest["web_accessible_resources"]:
                if fnmatch.fnmatch(contained_file, whitelisted) and ".htm" in contained_file \
                        and contained_file != background_page:
                    content = extension_zip.read(contained_file)
                    soup = BeautifulSoup(content, features="html.parser")
                    scripts = soup.find_all("script")
                    for script in scripts:
                        if "src" in script.attrs:
                            script_src = urljoin(contained_file, script["src"].split("?")[0].split("#")[0])
                            all_scripts.add(script_src)
                        elif script.string:
                            war_scripts += "// New inline (from %s)\n" % contained_file
                            war_scripts += beautify_script(script.string, extension_zip.filename) + "\n"

    return war_scripts + pack_and_beautify(extension_zip, all_scripts)


def get_wars_v3(manifest, extension_zip):
    """ Extracts the web accessible resources if manifest version 3. """

    all_scripts = set()
    war_scripts = ""

    if "web_accessible_resources" in manifest:
        try:
            background_page = manifest.get("background", {}).get("page")
        except AttributeError:
            background_page = None
        whitelisted_list = set()
        for el in manifest["web_accessible_resources"]:
            if 'resources' in el:
                for res in el['resources']:
                    whitelisted_list.add(res)
        for contained_file in extension_zip.namelist():
            for whitelisted in whitelisted_list:
                if fnmatch.fnmatch(contained_file, whitelisted) and ".htm" in contained_file \
                        and contained_file != background_page:
                    content = extension_zip.read(contained_file)
                    soup = BeautifulSoup(content, features="html.parser")
                    scripts = soup.find_all("script")
                    for script in scripts:
                        if "src" in script.attrs:
                            script_src = urljoin(contained_file, script["src"].split("?")[0].split("#")[0])
                            all_scripts.add(script_src)
                        elif script.string:
                            war_scripts += "// New inline (from %s)\n" % contained_file
                            war_scripts += beautify_script(script.string, extension_zip.filename) + "\n"

    return war_scripts + pack_and_beautify(extension_zip, all_scripts)


@benchmark
def unpack_extension(extension_crx, dest):
    """
    Call this function to extract the manifest, content scripts, background scripts, and WARs.

    :param extension_crx: str, path of the packed extension to unpack;
    :param dest: str, path where to store the extracted extension components.
    """

    extension_id = os.path.basename(extension_crx).split('.crx')[0]
    dest = os.path.join(dest, extension_id)

    try:
        extension_zip = ZipFile(extension_crx)
        manifest = json.loads(read_from_zip(extension_zip, "manifest.json"))
    except:
        return

    if "theme" in manifest:
        # Just quick exit to remove the themes
        return

    manifest_version = manifest.get("manifest_version", -1)
    if manifest_version not in (2, 3):
        logging.error('Only unpacking extensions with manifest version 2 or 3')
        # Considering only extensions with manifest versions 2 or 3
        return

    if not os.path.exists(dest):
        os.makedirs(dest)

    with open(os.path.join(dest, "manifest.json"), "w") as fh:
        fh.write(json.dumps(manifest, indent=2))

    content_scripts = get_all_content_scripts(manifest, extension_zip)
    # combine into contentscript.js to be compatible with doublex.py and examples
    with open(os.path.join(dest, "contentscript.js"), "w") as fh:
        fh.write(content_scripts)

    if manifest_version == 2:
        backgrounds = get_all_background_scripts_v2(manifest, extension_zip)
    else:
        backgrounds = get_all_background_scripts_v3(manifest, extension_zip)
    with open(os.path.join(dest, "background.js"), "w") as fh:
        fh.write(backgrounds)

    if manifest_version == 2:
        wars = get_wars_v2(manifest, extension_zip)
    else:
        wars = get_wars_v3(manifest, extension_zip)
    with open(os.path.join(dest, "wars.js"), "wb") as fh:
        fh.write(wars.encode())

    logging.info('Extracted the components of %s in %s', extension_crx, dest)


def extract_all(crx_path):
    """ Debug. """

    extension_zip = ZipFile(crx_path)
    extension_zip.extractall()


def producer(file_queue: Queue, root):
    for root, dirs, files in os.walk(root):
        for file in files:
            if file.endswith(".crx"):
                file_queue.put(os.path.join(root, file))
    file_queue.put(None)


def consumer(queue: Queue, args, process_id, counter: Value):
    while True:
        logging.log(logging.INFO, f'[{process_id}] Current items in queue: {queue.qsize()}')
        item = queue.get()
        if item is None:
            logging.log(logging.INFO, f'[{process_id}] Exiting queue...')
            queue.put(None)
            break
        logging.log(logging.INFO, f'[{process_id}] Started unpacking item: {item}')
        dest = args.d or os.path.dirname(item)
        unpack_extension(extension_crx=item, dest=dest, benchmark=args.b)
        logging.log(logging.INFO, f'[{process_id}] Finished unpacking item: {item}')
        counter.value += 1


@benchmark
def unpack_directory(args):
    process_count = args.pc
    queue = Queue()
    counter = Value('i', 0)
    logging.info(f'Starting producer process...')
    input_process = Process(target=producer, args=(queue, args.s))
    input_process.start()
    logging.info(f'Starting consumer {process_count} processes...')
    unpack_process = [Process(target=consumer,
                              args=[queue, args, process_id, counter],
                              name=f'UnpackProcess-{process_id}') for process_id in range(process_count)]
    for process in unpack_process:
        process.start()
    all_processes = unpack_process + [input_process]
    for process in all_processes:
        process.join()
    logging.info(f'Processed {counter.value} extensions.')


def main():
    """ Parsing command line parameters. """

    parser = argparse.ArgumentParser(prog="unpack",
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     description="Unpacks a Chrome extension (if manifest v2 or v3)"
                                                 " and extracts its manifest, content scripts, "
                                                 "background scripts/page, and WARs")

    parser.add_argument("-s", "--source", dest="s", metavar="path", type=str,
                        required=True, help="path of the packed extension to unpack or directory containing extensions")
    parser.add_argument("-d", "--destination", dest="d", metavar="path", type=str,
                        help="path where to store the extracted extension components"
                             " (note: a specific folder will be created)")
    parser.add_argument("-b", "--benchmark", dest="b", action="store_true",
                        help="limit on how many extensions should be unpacked")
    parser.add_argument("-pc", "--process-count", dest='pc', metavar="int", type=int,
                        default=1, choices=range(1, 11),
                        help="the number of processes to use for the analysis. "
                             "Default: 1 "
                             "Maximum: 10 "
                             "This argument is only used if source is a directory")

    args = parser.parse_args()
    source = args.s

    if os.path.isdir(source):
        logging.info(f'Unpacking extensions in directory: {source}')
        unpack_directory(args, benchmark=args.b)
    else:
        logging.info(f'Unpacking extension: {source}')
        dest = args.d or os.path.dirname(source)
        unpack_extension(extension_crx=source, dest=dest, benchmark=args.b)


if __name__ == "__main__":
    main()
