// This fetch call to the apigateway targets to get the visit registered to the back-end.
//  
var apiUrl = 'https://localhost:8443';

fetch(apiUrl, {
  method: 'GET',
  credentials: 'include',
  headers: {
    "X-Ivm-Client": "ivmanto.dev"
    // 'Content-Type': 'application/x-www-form-urlencoded',
  }
}).then(function(response) {
  if (response.status == 200) {
    console.log("done...", response.headers.get("set-cookie"))
  } else {
    console.error(response.status)
  }
});
