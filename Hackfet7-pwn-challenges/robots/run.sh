sudo docker build -t robots .
sudo docker run -dp 1337:5000 --name pwn_robots_2 --privileged robots
