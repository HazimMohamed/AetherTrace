hello_world:
	docker run -it --rm \
	  -v "$$PWD"/runtime-fs:/runtime-fs \
	  -v "$$PWD"/c:/c \
	  -v "$$PWD"/exec:/exec \
	  ubuntu:18.04 \
	  bash -c \
	  "export DEBIAN_FRONTEND=noninteractive && apt update && apt install -y gcc libc6-dev && gcc -o /exec/hello_world /c/hello_world.c"
	 python3 ./trace/trace.py --target hello_world