from os import urandom

from core.dkek import write_binary_file, write_text_file

def gen_sample_messages(path_root: str):
    
    binary_msg = urandom(200)
    write_binary_file(f'{path_root}/binary_msg.bin', binary_msg)

    text_msg = 'one two three four five six seven eight nine ten eleven twelve thirteen fourteen'
    write_text_file(f'{path_root}/text_msg.txt', text_msg)

def gen_sample_data(path_root: str = '.'):
    gen_sample_messages(path_root)