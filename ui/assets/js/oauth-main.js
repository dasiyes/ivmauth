let lh = window.location.host
if (lh.startsWith('localhost')) {
  document.cookie = "c=755477323135-ai15g84hp3ht4vn1lutcibpa4es22m49.apps.googleusercontent.com; path=/";
} else {
  document.cookie = "c=755477323135-ai15g84hp3ht4vn1lutcibpa4es22m49.apps.googleusercontent.com; secure=true; path=/";
}

var form = document.getElementById('login');
var buttonE1 = document.getElementById('e1');

buttonE1.addEventListener('click', function () {
  form.classList.add('error_1');
  setTimeout(function () {
    form.classList.remove('error_1');
  }, 3000);
});
