ssh -i "carlos.pem" ec2-user@54.161.55.107
scp -i "carlos.pem" -r go-backend/main ec2-user@54.161.55.107:app/
cd app/go-backend
go run main.go