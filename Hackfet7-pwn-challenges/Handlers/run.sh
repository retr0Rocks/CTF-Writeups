sudo docker build -t handlers .
sudo docker run -dp 1338:5000 --name pwn_handlers --privileged handlers
