sudo docker build -t oneshot .
sudo docker run -dp 1337:5000 --name challenge_onehsot --privileged oneshot
