
package encryption

import (
    "github.com/SSSaaS/Sssa-golang"
    "log"
  )



  func Secrets(){
    f, _ := sssa.Create(4, 10, "Hey Ram") 
    log.Println("These are the secrets %s", f)
  }
