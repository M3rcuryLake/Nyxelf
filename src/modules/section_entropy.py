from elftools.elf.elffile import ELFFile
import math

def calculate_entropy(data):

    byte_frequencies = [0] * 256
    total_bytes = len(data)

    for byte in data:
        byte_frequencies[byte] += 1

    entropy = 0
    for count in byte_frequencies:
        if count > 0:
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)

    return f"{entropy:.4f}"

def analyze_elf_sections(file_path):
    section_entropy = dict()
    with open(file_path, 'rb') as f:
        elf = ELFFile(f)

        for section in elf.iter_sections():
            section_name = section.name
            section_data = section.data()
            section_entropy[section_name] = calculate_entropy(section_data)
        section_entropy.pop('') if '' in section_entropy.keys() else None
        return section_entropy
