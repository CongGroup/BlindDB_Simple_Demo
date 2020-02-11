/* keep track of which salts have been used. */
var form, usedIvs = {'':1}, usedSalts = {'':1};
var redisip = 'http://54.169.16.20:8081'

/* enter actions */
var enterActions = {
  password: doPbkdf2,
  salt: doPbkdf2,
  iter: doPbkdf2
};

function loaded() {
  form = new formHandler('theForm', enterActions);
  form._extendedKey = [];
  sjcl.random.startCollectors();
  document.getElementById("password").focus();
}

/* there's probaby a better way to tell the user something, but oh well */
function error(x) {
  alert(x);
}

/* compute PBKDF2 on the password. */
function doPbkdf2(decrypting) {
  var v = form.get(), salt=v.salt, key, hex = sjcl.codec.hex.fromBits, p={},
      password = v.password;
  
  p.iter = v.iter;
  
  if (password.length == 0) {
    if (decrypting) { error("Can't decrypt: need a password!"); }
    return;
  }
  
  if (salt.length === 0 && decrypting) {
    error("Can't decrypt: need a salt for PBKDF2!");
    return;
  }
  
  if (decrypting || !v.freshsalt || !usedSalts[v.salt]) {
    p.salt = v.salt;
  }
  
  p = sjcl.misc.cachedPbkdf2(password, p);
  form._extendedKey = p.key;
  v.key = p.key.slice(0, v.keysize/32);
  v.salt = p.salt;
  
  form.set(v);
  form.plaintext.el.select();
}

function post(path) {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (xhttp.readyState == 4 && xhttp.status == 200) {
      document.getElementById("demo").innerHTML = xhttp.responseText;
    }
  };
  xhttp.open("POST", path, true);
  xhttp.send();
}
/* Encrypt a message */
function doEncrypt() {
  var v = form.get(), iv = v.iv, password = v.password, key = v.key, adata = v.adata, aes, plaintext=v.plaintext, rp = {}, ct, p;


  if (plaintext === '' && v.ciphertext.length) { return; }
  if (v.hdata == '' || v.plaintext == '') {return; }
  if (key.length == 0 && password.length == 0) {
    error("need a password or key!");
    return;
  }
  
  p = { adata:v.adata,
        iter:v.iter,
        mode:v.mode,
        ts:parseInt(v.tag),
        ks:parseInt(v.keysize) };
  if (!v.freshiv || !usedIvs[v.iv]) { p.iv = v.iv; }
  if (!v.freshsalt || !usedSalts[v.salt]) { p.salt = v.salt; }
  ct = sjcl.encrypt(password || key, plaintext, p, rp).replace(/,/g,",\n");

  v.iv = rp.iv;
  usedIvs[rp.iv] = 1;
  if (rp.salt) {
    v.salt = rp.salt;
    usedSalts[rp.salt] = 1;
  }
  v.key = rp.key;
  
  var h, hdata = v.hdata;
  hdata = v.hdata + sjcl.codec.hex.fromBits(v.key);
  h = sjcl.hash.sha256.hash(hdata);
  h = sjcl.codec.base64.fromBits(h);
  ct["hdata"] = h;
  zz = sjcl.json.decode(ct);
  zz["hdata"] = h;
  ct = sjcl.json.encode(zz);

  v.shkey = h;
  v.ciphertext = sjcl.codec.base64.fromBits(zz.ct);

  var base64_CT = sjcl.codec.base64.fromBits(zz.ct);

  var myiv = sjcl.codec.base64.fromBits(v.iv);
  post(redisip + "/put/" + v.shkey + "/" + myiv + v.ciphertext);
  form.set(v);
  form.ciphertext.el.select();
}

function storeData() {
  var v = form.get();
  var shkey = v.shkey;
  var hciphertext = v.ciphertext;
  var iv = sjcl.codec.base64.fromBits(v.iv);
  post(redisip + "/put/" + shkey + "/" + iv + hciphertext);
}

function hashPrimaryKey() {
  var v = form.get();
  var pkey = v.gpkey;
  var password = v.password, key = v.key;

  if (pkey === '') { return; }
  if (key.length == 0 && password.length == 0) {
    error("need a password or key!");
    return;
  }

  var p = {salt: v.salt, iter: v.iter};
  tmp = sjcl.misc.cachedPbkdf2(password, p);
  password = tmp.key.slice(0,p.ks/32);
  p.salt = tmp.salt;

  v.salt = tmp.salt;
  v.key = tmp.key;
  console.log(tmp.key + "*" + tmp.salt);

  var h, hdata;
  hdata = pkey + sjcl.codec.hex.fromBits(v.key);
  h = sjcl.hash.sha256.hash(hdata);
  h = sjcl.codec.base64.fromBits(h);
  v.ghkey = h;
  form.set(v);
}

function getCiphertext() {
  var v = form.get();
  $.getJSON(
    redisip + "/g/" + v.ghkey, 
    function(ct) {
      console.log(ct.Value);
      console.log(ct.Value === null);
      if (ct.Value === null) { 
        v.gct = 'No Data';
        form.set(v);
      } else {
        v.gct = ct.Value.slice(24);
        v.iv = sjcl.codec.base64.toBits(ct.Value.slice(0,24));
        form.set(v);
      }
    }
  );

}

function decryptCiphertext() {
  var v = form.get(), iv = v.iv, key = v.key, adata = v.adata, aes, ciphertext=v.gct, rp = {};

  if (ciphertext.length === 0) { return; }
  if (!v.password && !v.key.length) {
    error("Can't decrypt: need a password or key!"); return;
  }

  ciphertext = sjcl.codec.base64.toBits(ciphertext);
  if (iv.length === 0) {
    error("Can't decrypt: need an IV!"); return;
  }
  if (key.length === 0) {
    if (v.password.length) {
      doPbkdf2(true);
      key = v.key;
    }
  }
  aes = new sjcl.cipher.aes(key);
  
  try {
    v.gpt = sjcl.codec.utf8String.fromBits(sjcl.mode[v.mode].decrypt(aes, ciphertext, iv, v.adata, v.tag));
  } catch (e) {
    error("Can't decrypt: " + e);
  }

  form.set(v);

}

function extendKey(size) {
  form.key.set(form._extendedKey.slice(0,size));
}

function randomize(field, words, paranoia) {
  form[field].set(sjcl.random.randomWords(words, paranoia));
  if (field == 'salt') { form.key.set([]); }
}
