

package users

import (
      "fmt"
      "net/http"
      "encoding/json"
    )


func ValidateToken(w http.ResponseWriter, r *http.Request){

    params := r.URL.Query()
    fmt.Println(params)

    result := Response{}
    result.Message = "Tatti kha le chutiye"
    output, _ := json.Marshal(result)

    w.Header().Set("content-type", "application/json")
    w.Write([]byte(output))



}
