

package settings

import (
  "gopkg.in/mgo.v2"
  "encoding/json"
  "os"
  "fmt"
  "log"
)







//This is the json configuration object in which the config.json file will be loaded
type JsonConfiguration struct{
    Mongo map[string]string

}



//This is the system wide configuration struct in which all the paramteres for
// application configuration will be stored.
type  Configuration struct{
    dbsession *mgo.Session
    config JsonConfiguration


}

func (c *Configuration) ReadConfigFile() JsonConfiguration {

    file, fileerror := os.Open("settings/config.json")
    defer file.Close()
    if fileerror != nil{
      fmt.Println(fileerror)
    }

    decoder := json.NewDecoder(file)
    configuration := JsonConfiguration{}
    err := decoder.Decode(&configuration)
    if err != nil {
        fmt.Println("error:", err)
    }

    c.config = configuration
    return configuration
}




func (c *Configuration) NewDBSession() (*mgo.Session, error) {

    //session, err := mgo.Dial("localhost:27017")
    mongoDBDialInfo := &mgo.DialInfo{Addrs: []string{c.config.Mongo["IP"]},
        Database: c.config.Mongo["DBname"],
        Username: c.config.Mongo["Username"],
        Password: c.config.Mongo["Password"],
    }

    session, err := mgo.DialWithInfo(mongoDBDialInfo)
    if err != nil {
          log.Fatalf("CreateSession: %s\n", err)
    }

    session.SetMode(mgo.Monotonic, true)
    return session, err
}

func(c *Configuration) CopySession() *mgo.Session {
    return c.dbsession.Copy()
}

func(c *Configuration) GetCollection(db string, col string) *mgo.Collection {
    return c.dbsession.DB(db).C(col)
}

func(c *Configuration) Close() {
    if(c.dbsession != nil) {
        c.dbsession.Close()
  }
}
