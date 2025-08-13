from parser import *
from builder.c_header_builder import *
import argparse

if __name__ != "__main__":
    exit(0)

args = argparse.ArgumentParser()
args.add_argument("--pdb", help="Path to pdb file", required=False)
args.add_argument("--json", help="Path to json file", required=False)
args.add_argument("--nt", help="Path to NT kernel", required=False)
args.add_argument("-o", help="Path to output file", required=True)
args = args.parse_args()

if not args.pdb and not args.json:
    if not args.nt:
        pdb_file = retrieve_pdb()
    else:
        pdb_file = retrieve_pdb(ntoskrnl_path=args.nt)
elif args.pdb:
    pdb_file = args.pdb

if not args.json:
    json_file = pdb_export_json(pdb_file)

data = parse_json_file(json_file)
c_header_file = build_c_header_file(data)

with open(args.o, "w") as f:
    f.write(c_header_file)