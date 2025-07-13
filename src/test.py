import logging
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="[%(processName)s] %(asctime)s %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

setup_logging()

import modules.prepare_projects


def main():
    modules.prepare_projects.get_clang_dependencies()


if __name__ == "__main__":
    main()
