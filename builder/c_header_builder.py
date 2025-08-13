"""
c_header_builder.py - build to a C header file
"""

ALLOWED_ALPHABETS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_'

def build_c_header_file(json_data) -> str:

    buffers = []

    define_u8 =  '#define _ntksp_u8  unsigned char'
    define_u16 = '#define _ntksp_u16 unsigned short'
    define_u32 = '#define _ntksp_u32 unsigned int'
    define_u64 = '#define _ntksp_u64 unsigned long long'

    buffers.append(define_u8)
    buffers.append(define_u16)
    buffers.append(define_u32)
    buffers.append(define_u64)
    buffers.append('')

    for func in json_data['functions']:
        if not all(c in ALLOWED_ALPHABETS for c in func['name']):
            continue
        buffers.append(f"const _ntksp_u64 off_fn_{func['name']} = {func['rva']}ULL;")

    buffers.append('')

    for _global in json_data['globals']:
        if not all(c in ALLOWED_ALPHABETS for c in _global['name']):
            continue
        buffers.append(f"const _ntksp_u64 off_g_{_global['name']} = {_global['rva']}ULL;")

    return '\n'.join(buffers)