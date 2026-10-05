set -eu
systemctl enable cats-validator.service
systemctl restart cats-validator.service
systemctl is-active --quiet cats-validator.service
