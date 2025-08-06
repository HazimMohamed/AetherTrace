FROM ubuntu:18.04
LABEL authors="hazimmohamed"

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y gcc libc6-dev
VOLUME ["/exec", "/c"]
COPY ["./docker/compile.sh", "/compile.sh"]
RUN chmod +x /compile.sh
ENTRYPOINT "/compile.sh"
#CMD "--version"