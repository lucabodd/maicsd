package daily_tasks

import (
    "net/mail"
    "strings"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "go.mongodb.org/mongo-driver/bson"
    ldap_client "github.com/lucabodd/go-ldap-client"
    . "github.com/lucabodd/maicsd/pkg/utils"
    "log"
    "os"
    "time"
    "encoding/json"
    "context"
    "strconv"
    "strings"
)

type Mailtemplates struct {
	Standard string
	Noreset  string
	Nobutton string
}

type User struct {
	Sys_username string `bson:"sys_username"`
	Email string `bson:"email"`
	Role string `bson:"role"`
	Key_last_unlock string `bson:"key_last_unlock"`
	PubKey string `bson:"pubKey"`
	Password string `bson:"password"`
	Otp_secret string `bson:"otp_secret"`
	PwdChangedTime string `bson:"pwdChangedTime"`
	PwdAccountLockedTime *string `bson:"pwdAccountLockedTime"`
}

//slow tasks
/************************************
	Task executed daily
*************************************/
func PasswordExpire(mdb *mongo.Client, mongo_instance string, skdc_dir string, admin_mail string, ldap *ldap_client.LDAPClient){
	log.Println("[*] Undergoing key expiration procedure")
	log.Println(" |___")
	// vars
	users := mdb.Database(mongo_instance).Collection("users")
	warningDelta:=75
	expirationDelta:=90
	//OPening mail templates
	file, err := os.Open(skdc_dir+"etc/mailtemplates.json")
	Check(err)
	defer file.Close()
	decoder := json.NewDecoder(file)
	Templates := Mailtemplates{}
	err = decoder.Decode(&Templates)
	Check(err)

	findOptProj := options.Find().SetProjection(bson.M{"email":1, "sys_username": 1, "pwdChangedTime":1, "pwdAccountLockedTime":1})
	cur, err := users.Find(context.TODO(), bson.M{"sys_username": "luca.bodini"}, findOptProj)
	Check(err)
	defer cur.Close(context.TODO())
	for cur.Next(context.TODO()) {
		var user User
		err := cur.Decode(&user)
		Check(err)
		diff := TimeHoursDiff(user.PwdChangedTime)
		if (diff >= warningDelta && diff < expirationDelta) {
			//Mail parameters
			subject := "SKDC - User "+user.Sys_username+" password is expiring soon"
			txt := "Your password is "+strconv.Itoa(diff)+" old and will expire in "+strconv.Itoa(expirationDelta-diff)+" days. please, log in clicking on the button below and change it as soon as possible"
			body := strings.Replace(Templates.Standard,"%s",txt,-1)
			err = SendMail("127.0.0.1:25", (&mail.Address{"SKDC", admin_mail}).String(), subject, body, []string{(&mail.Address{user.Sys_username, user.Email}).String()})
			Check(err)
			log.Println("    |- Password expiration notifyed to user "+user.Sys_username)
		} else if (diff >= expirationDelta && user.PwdAccountLockedTime==nil) {
			format := "20060102150405Z"
			now := time.Now().Format(format)
			_, err = ldap.AddUserAttribute(user.Sys_username, "pwdAccountLockedTime", now)
			Check(err)
			_, err = users.UpdateOne(context.TODO(), bson.M{"email":user.Email }, bson.M{ "$set": bson.M{ "pwdAccountLockedTime" : now, "key_last_unlock": "19700101000010Z" }, "$unset": bson.M{"otp_secret":1, "pubKey":1}})
			Check(err)
			_, err = ldap.SetUserAttribute(user.Sys_username, "sshPublicKey", "")
			Check(err)
			subject := "SKDC - User "+user.Sys_username+" password is expired"
			txt := "Your password is "+strconv.Itoa(diff)+" days old and is expired. Your account has been locked for security reason, please ask Administrators to unlock your account."
			body := strings.Replace(Templates.Nobutton,"%s",txt,-1)
			err = SendMail("127.0.0.1:25", (&mail.Address{"SKDC", admin_mail}).String(), subject, body, []string{(&mail.Address{user.Sys_username, user.Email}).String()})
			Check(err)
			log.Println("    |- Account for user "+user.Sys_username+" Locked due to password expiration")
		}
	}
	log.Println("[+] Password expiration carried according to policy")
}
