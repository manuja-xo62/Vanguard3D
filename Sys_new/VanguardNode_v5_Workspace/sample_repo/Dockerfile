FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3
# Deliberately missing USER directive to run as root
CMD ["python3", "-m", "http.server"]