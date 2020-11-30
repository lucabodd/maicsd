package utils

import (
    ansible "github.com/lucabodd/go-ansible"
    "strings"
    json "github.com/tidwall/gjson"
    "log"
    "time"
)

func AnsibleParseResult(res *ansible.PlaybookResults, err error) (string, string){
    var conn string
    var connection_detail string

    if err != nil {
        if(res.Unreachable > 0){
            if (strings.Contains(res.RawStdout, "ssh_exchange_identification")) {
                conn = "proxy-refuse"
                connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts.*.msg").String()
                // Adding start & end time
                connection_detail += "<br><br> Start Time:<br>"+ json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.start").String()
                connection_detail += "<br><br> End Time:<br>" + json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.end").String()
            } else if(strings.Contains(res.RawStdout, "No route to host") || strings.Contains(res.RawStdout, "Connection refused") || strings.Contains(res.RawStdout, "Connection timed out")){
                conn = "unreachable"
                connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts.*.msg").String()
                // Adding start & end time
                connection_detail += "<br><br> Start Time:<br>"+ json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.start").String()
                connection_detail += "<br><br> End Time:<br>" + json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.end").String()
            } else if (strings.Contains(res.RawStdout, "Permission denied (publickey")) {
                conn = "unauthorized"
                connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts.*.msg").String()
                // Adding start & end time
                connection_detail += "<br><br> Start Time:<br>"+ json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.start").String()
                connection_detail += "<br><br> End Time:<br>" + json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.end").String()
            } else {
                conn = "unknown"
                log.Println("ANSIBLE RUN ERROR -> ")
                log.Print(err)
                log.Println("ANSIBLE RUN STDOUT -> " + res.RawStdout)
                connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts.*.stderr").String()
            }
        } else if (res.Failures > 0) {
            if (strings.Contains(res.RawStdout, "maics-ward-undeployed")){
                conn = "maics-ward-undeployed"
                connection_detail = json.Get(res.RawStdout, "plays.0.tasks.2.hosts.*.msg").String()
                // Adding start & end time
                connection_detail += "<br><br> Start Time:<br>"+ json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.start").String()
                connection_detail += "<br><br> End Time:<br>" + json.Get(res.RawStdout,"plays.0.tasks.0.task.duration.end").String()
            } else {
                conn = "unknown"
                log.Println("ANSIBLE RUN ERROR -> ")
                log.Print(err)
                log.Println("ANSIBLE RUN STDOUT -> " + res.RawStdout)
                connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts.*.stderr").String()
            }
        } else {
            conn = "unknown"
            log.Println("ANSIBLE RUN ERROR -> ")
            log.Print(err)
            log.Println("ANSIBLE RUN STDOUT -> " + res.RawStdout)
            connection_detail = json.Get(res.RawStdout, "plays.0.tasks.0.hosts.*.stderr").String()
        }
    } else {
        conn = "true"
        //format := "2020-10-29T23:56:32.777053Z"
        now := time.Now().Format(time.RFC3339)
        connection_detail = "Connected.<br>Last update: "+ now

    }
    connection_detail = strings.Replace(connection_detail, "\n", "", -1)
    connection_detail = strings.Replace(connection_detail, "  ", "", -1)

    return conn, connection_detail
}
