FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3
# Deliberately missing USER directive to run as root
USER vanguard_svc # [VANGUARD NANO-PATCH APPLIED]
CMD ["python3", "-m", "http.server"] # [VANGUARD MANUAL REVIEW REQUIRED] # [VANGUARD MANUAL REVIEW REQUIRED]