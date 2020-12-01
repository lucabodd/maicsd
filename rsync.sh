for i in $(seq 1 100000); do rsync -avz * root@maics-appliance-01:/root/go/src/github.com/lucabodd/maicsd --progress; sleep 1; done
