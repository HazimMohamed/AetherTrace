from pathlib import Path

import docker
import os

COMPILATION_CONTAINER = {
    'name': 'x8664-compiler',
    'tag': '0.6'
}
FULL_CONTAINER_NAME = f'{COMPILATION_CONTAINER["name"]}:{COMPILATION_CONTAINER["tag"]}'
FORCE_REBUILD = False

def cross_compile(target: str):
    client = docker.from_env()
    if FORCE_REBUILD:
        client.images.remove(FULL_CONTAINER_NAME, force=True)

    image_exists = any(FULL_CONTAINER_NAME in img.tags for img in client.images.list())
    if not image_exists:
        print(f'Building a new docker image for cross compilation: {FULL_CONTAINER_NAME}')
        client.images.build(
            path='./',
            dockerfile='./docker/x8664_compiler.Dockerfile',
            tag=FULL_CONTAINER_NAME
        )

    os.makedirs('./exec', exist_ok=True)

    print('Creating a new container for cross compilation')
    container = client.containers.create(
        FULL_CONTAINER_NAME,
        entrypoint="bash",
        command=["-c", f"./compile.sh {target}"],
        volumes={
            str(Path('./c').resolve()): {'bind': '/c', 'mode': 'rw'},
            str(Path('./exec').resolve()): {'bind': '/exec', 'mode': 'rw'}
        },
    )

    print('Running cross compilation')
    container.start()
    result = container.wait()

    exit_code = result.get("StatusCode")
    if exit_code != 0:
        print(f"Error! Exit code: {exit_code}")

    print("Compiler output:")
    for line in container.logs(stream=True):
        print(line.decode().strip())

    print('Cleaning up.')
    container.remove()

if __name__ == '__main__':
    cross_compile('hello_world')
