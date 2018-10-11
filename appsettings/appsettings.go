
package appsettings

import (
  "log"
  "net/http"
  "fmt"
  "time"
  "encoding/json"
  "github.com/dgrijalva/jwt-go"
  "gopkg.in/mgo.v2"
  //"gopkg.in/mgo.v2/bson"
  "github.com/bitly/go-simplejson"
  r "gopkg.in/gorethink/gorethink.v4"



)

type AppError struct {
    Message string `json:"message"`
    Error bool `json:"error"`
    Success bool `json:"success"`

}


type AppResponse struct {
    Message string `json:"message"`
    Error bool `json:"error"`
    Success bool `json:"success"`
    Data map[string]interface{} `json:"data"`
}



type AppLoginResponse struct {
    Message string `json:"message"`
    Error bool `json:"error"`
    Success bool `json:"success"`
    Token string `json:"token"`
}



func (err *AppError) printError() string {
    return fmt.Sprintf("%s %s %s", err.Message, err.Error, err.Success)
}


type user struct{
    Username string `json:"username"`
    Password string `json:"password"`
    UserId string `json:"userid"`
    Email string `json:"email"`
    CreatedAt time.Time `json:"createdat"`
    PhoneNumber string `json:"phonenumber"`

}


type authorization struct {
	Username string `json:"username"`
	Password string   `json:"password"`
	jwt.StandardClaims
}



type ContextHandler struct {
  	*AppContext
  	//ContextedHandlerFunc is the interface which our Handlers will implement
  	Handler func(*AppContext, http.ResponseWriter, *http.Request)(int, error)
}

//AppContext provides the app context to handlers.  This *cannot* contain request-specific keys like
//sessionId or similar.  It is shared across requests.
type AppContext struct {
    Db    *mgo.Session
    Config *simplejson.Json
    RethinkSession *r.Session
}


//We use pointer here because all the requests will refer to the same ContextHandler instance//
//This will be treated as a struct method of struct ContextHandler
func (ahandler ContextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // Updated to pass ah.appContext as a parameter to our handler type.
    status, err := ahandler.Handler(ahandler.AppContext, w, r)
    if err != nil {
        switch status {
        case http.StatusNotFound:
            http.NotFound(w, r)
            // And if we wanted a friendlier error page, we can
            // now leverage our context instance - e.g.
            // err := ah.renderTemplate(w, "http_404.tmpl", nil)
          case http.StatusInternalServerError:
              http.Error(w, http.StatusText(status), status)
        default:
            http.Error(w, http.StatusText(405), 405)
        }
    }
}



func CheckAuth(h http.Handler, appcontext *AppContext) http.Handler {
    log.Println("Checkauth handler added")
    f := func( w http.ResponseWriter, r *http.Request) {
        authorizationToken := r.Header.Get("Authorization")
        if authorizationToken != ""{
            asecret := *appcontext.Config.Get("JWT")
            fsecret, _ := asecret.Get("secret").String()
            secret := []byte(fsecret)
            var credentials authorization
            token, err := jwt.ParseWithClaims(authorizationToken, &credentials, func(t *jwt.Token) (interface{}, error) {
                return []byte(secret), nil
            })

            if err == nil && token.Valid {
                //If everything is fine serve the Http request
                //Creating a copy of the
                /*
                session := appcontext.Db.Copy()
                defer session.Close()
                c := session.DB("feynmen_main_db").C("users")

                //Creating an instance of the struct user, address of which will be passed to mongosession query
                userdata := new(user)
                // Trying to find the derciphered username and password from the mongodb
                dberr := c.Find(bson.M{"username": credentials.Username, "password": credentials.Password}).One(&userdata)
                //If the username and password deciphered from the mongodb couldt be found
                if dberr != nil {
                    json.NewEncoder(w).Encode(&FeynError{"User couldnt be found", true, false})
                    return
                }
                */
                log.Println("Tne user has been authenticated")
                h.ServeHTTP( w, r)
                return
                } else {
                      json.NewEncoder(w).Encode(&AppError{"Token is invalid", true, false})
                      return
                      }
          }else{
              json.NewEncoder(w).Encode(&AppError{"Authorization header is Missing", true, false})
              return
            }
    }
    return http.HandlerFunc(f)
}


func RecoverHandler(next http.Handler) http.Handler {
    log.Println("Recover handler added")

  	fn := func(w http.ResponseWriter, r *http.Request) {
    		defer func() {
      			if err := recover(); err != nil {
        				log.Printf("panic: %+v", err)
                json.NewEncoder(w).Encode(&AppError{"Unknown error happened", true, false})
                return
      			}
    		}()

    		next.ServeHTTP(w, r)
  	}

  	return http.HandlerFunc(fn)
  }


func loggingHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		t1 := time.Now()
		next.ServeHTTP(w, r)
		t2 := time.Now()
		log.Printf("[%s] %q %v\n", r.Method, r.URL.String(), t2.Sub(t1))

	}

	return http.HandlerFunc(fn)
}

//This function creates a dbconnection
func Initdb(configfile  *simplejson.Json) *mgo.Session{
    dbconfig := configfile.Get("Mongo")
    dbip, _ := dbconfig.Get("IP").String()
    dbname, _ := dbconfig.Get("Dbname").String()
    username, _ := dbconfig.Get("username").String()
    password, _ := dbconfig.Get("password").String()

    mongoDBDialInfo := &mgo.DialInfo{Addrs: []string{dbip},
        Database: dbname,
        Username: username,
        Password: password,
    }

    session, err := mgo.DialWithInfo(mongoDBDialInfo)
    if err != nil {
          log.Fatal("CreateSession: %s\n", err)
    }

    session.SetMode(mgo.Monotonic, true)
    return session
}

//This function creates a dbconnection
func InitRethinkdb(configfile  *simplejson.Json, address string) *r.Session{
    dbconfig := configfile.Get("rethinkdb")
    username, _ := dbconfig.Get("username").String()
    password, _ := dbconfig.Get("password").String()

    session, err := r.Connect(r.ConnectOpts{
    Address: address,
    Username: username,
    Password: password,
})

    if err != nil {
          log.Fatal("CreateSession error for rethinkdb: %s\n", err)
    }

    return session
}
