import argparse

class Config:
    def __init__(self, target, static_libraries):
        self.target = target
        self.static_libraries = static_libraries

def parse_config():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', type=str, required=True, help='Entry point for trace')
    parser.add_argument('--slibs', type=str, required=False,
                        nargs='+', help='Static libraries to load')
    args = parser.parse_args()
    return Config(args.target, args.slibs)