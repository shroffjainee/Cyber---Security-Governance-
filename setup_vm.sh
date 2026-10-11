#!/usr/bin/env bash
# Ubuntu 22.04 VM setup for real scans. Run:  bash setup_vm.sh
set -e
sudo apt-get update
sudo apt-get install -y openscap-scanner ssg-debderived python3-pip python3-venv wget gnupg ufw auditd
# Trivy (vulnerability scanner) from the official Aqua Security repository
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install -y trivy
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
echo "Setup complete. First scan:"
echo "  export CCM_PSEUDO_KEY='choose-a-secret'"
echo "  sudo -E .venv/bin/python collect_real.py --criticality 4 --exposure public"
