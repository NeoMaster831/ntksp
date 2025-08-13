"""
parser.py - parse nt kernel symbols
"""

from dotenv import load_dotenv
import pefile, uuid, struct, requests, os
import logging

load_dotenv()

PDB_SAVE_PATH = os.getenv("PDB_SAVE_PATH")
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


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    pth = retrieve_pdb(ntoskrnl_path="./ntoskrnl.exe")
