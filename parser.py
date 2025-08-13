"""
parser.py - parse nt kernel symbols
"""

from dotenv import load_dotenv
import pefile, uuid, struct, requests, os, subprocess, json
import logging

load_dotenv()

PDB_SAVE_PATH = os.getenv("PDB_SAVE_PATH")
JSON_SAVE_PATH = os.getenv("JSON_SAVE_PATH")
NT_KERNEL_DEFAULT_PATH = "C:\\Windows\\System32\\ntoskrnl.exe"


def retrieve_pdb(ntoskrnl_path: str = NT_KERNEL_DEFAULT_PATH, pdb_save_path: str = PDB_SAVE_PATH) -> str:
    """
    :param ntoskrnl_path: path to the ntoskrnl.exe executable.
    :param pdb_save_path: path to save the pdb file.
    :return: full path to the pdb file.
    """
    pe = pefile.PE(ntoskrnl_path)
    dbg = [e for e in pe.DIRECTORY_ENTRY_DEBUG if e.struct.Type == 2][0]  # CODEVIEW
    off = dbg.struct.PointerToRawData
    data = pe.__data__[off:off + 0x200]

    assert data[:4] == b'RSDS'

    guid = uuid.UUID(bytes_le=data[4:20])  # correct endianness

    age = struct.unpack("<I", data[20:24])[0]
    pdb = data[24:].split(b"\x00", 1)[0].decode()
    pdbname = os.path.basename(pdb)
    sig = f"{guid.hex.upper()}{age:X}"
    url = f"https://msdl.microsoft.com/download/symbols/{pdbname}/{sig}/{pdbname}"
    full_path = pdb_save_path + os.path.sep + pdbname

    if os.path.exists(full_path):
        logging.info(f"File {pdbname} already exists, skipping")
        return full_path

    if not os.path.exists(pdb_save_path):
        os.makedirs(pdb_save_path)

    logging.info(f"Downloading {url}...")

    r = requests.get(url, allow_redirects=True)
    r.raise_for_status()
    logging.info(f"Download complete. Writing to {full_path}...")

    with open(full_path, "wb") as f:
        f.write(r.content)

    logging.info("Done.")

    return full_path


def pdb_export_json(pdb_file_path, json_save_path: str = JSON_SAVE_PATH) -> str:

    pdb_exporter_path = 'bin' + os.sep + 'pdb_exporter'
    final_json_path = json_save_path + os.sep + 'out.json'

    if os.path.exists(final_json_path):
        return final_json_path

    if not os.path.exists(json_save_path):
        os.makedirs(json_save_path)

    if not os.path.exists(pdb_exporter_path):
        raise Exception(
            'There is no PDB exporter in bin/ directory. Did you run setup properly? Or are you running in wrong directory?'
        )

    logging.info("Running PDB exporter...")

    result = subprocess.run([
        pdb_exporter_path,
        pdb_file_path,
        final_json_path
    ]).returncode

    if result != 0 or not os.path.exists(final_json_path):
        raise Exception(
            "There were some errors while running PDB exporter"
        )

    logging.info(f"Saved JSON to {final_json_path}")

    return final_json_path

def parse_json_file(json_file_path):
    logging.info("Parsing JSON file...")
    with open(json_file_path, 'r') as f:
        contents = f.read()
    return json.loads(contents)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    pdb_file = retrieve_pdb(ntoskrnl_path="./ntoskrnl.exe")
    json_file = pdb_export_json(pdb_file)
    data = parse_json_file(json_file)