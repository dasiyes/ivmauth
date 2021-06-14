async function sendLogin(data = {}) {
  // postLogin('https://accounts.ivmanto.dev/auth', data)
  
  console.log("body:", data)

  fetch('https://accounts.ivmanto.dev/auth', {
    method: 'POST', // *GET, POST, PUT, DELETE, etc.
    mode: 'cors', // no-cors, *cors, same-origin
    cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
    credentials: 'include', // include, *same-origin, omit
    headers: {
      'Content-Type': 'application/json',
      // Base64 encoded client-id '674034520731-svnfvha7sbp971ubg0mckamaac07jhc2.apps.googleusercontent.com' + secret
      'x-ivm-client': 'Basic Njc0MDM0NTIwNzMxLXN2bmZ2aGE3c2JwOTcxdWJnMG1ja2FtYWFjMDdqaGMyLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tOk5JeWppYVd4S2VlbVZTdFFUODNNTWxuZQ==',
      'X-GRANT-TYPE': 'password',
      // 'Content-Type': 'application/x-www-form-urlencoded',
    },
    redirect: 'follow', // manual, *follow, error
    referrerPolicy: 'origin-when-cross-origin', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
    body: JSON.stringify(data) // body data type must match "Content-Type" header
  })
  .then(result => {
    console.log(result); // JSON data parsed by `data.json()` call
  });
}


// var apiUrl = 'https://accounts.ivmanto.dev/auth';

// fetch(apiUrl, {
//   method: 'POST',
//   credentials: 'include',
//   headers: {
//     "X-Ivm-Client": "ivmanto.dev"
//     // 'Content-Type': 'application/x-www-form-urlencoded',
//   }
// }).then(function(response) {
//   if (response.status == 200) {
//     console.log("done...", response.headers.get("set-cookie"))
//   } else {
//     console.error(response.status)
//   }
// });
