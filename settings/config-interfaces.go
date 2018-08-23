
package settings

import (
  "gopkg.in/mgo.v2"
)

type Databaser interface {
      NewDBSession() (*mgo.Session, error)
      CopySession() *mgo.Session
      GetCollection(db string, col string) *mgo.Collection
      Close()
}

type Configer interface {
    ReadConfigFile() JsonConfiguration

}

type App interface{
    Databaser
    Configer

}








//Following is the code to read paramteres from config.json
