// Certificados de cliente OQB: el mismo formato que verifica OQB-updater.
//
// Una consola se identifica por su Device ID (64 bits, de los fusibles del
// chip: no depende del PRODINFO, que el pack deja en blanco). La app lo
// muestra como codigo "XXXX-XXXX-XXXX-XXXX-CC", donde CC detecta errores al
// copiarlo.
//
// El certificado se publica en l/<archivo>.json. El nombre del archivo y la
// clave que cifra el nombre del cliente salen del Device ID, asi que el
// repositorio publico no dice de quien es cada certificado.
//
// Lo que se firma (Ed25519) es:
//   "OQB-CLIENTE-1\n" + idhex + "\n" + nombre + "\n" + fecha
// Sin la clave privada no se puede emitir uno valido, y como va atado al
// Device ID, copiarlo a otra consola no sirve.

export const CLAVE_PUBLICA_HEX = "2635d56a138ce071923af20bdf303348f4d51413cae7b3959afaf6a22ec301ed";

const te = new TextEncoder();
const td = new TextDecoder();

export function hexABytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function bytesAHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function bytesABase64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function base64ABytes(b64) {
  const s = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

async function sha256(texto) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", te.encode(texto)));
}

// "1A2B-3C4D-5E6F-7081-9F" -> idhex en minusculas, o lanza un error legible.
export async function leerCodigo(codigo) {
  const limpio = (codigo || "").toLowerCase().replace(/[^0-9a-f]/g, "");
  if (limpio.length !== 18) throw new Error("El código tiene que tener 18 letras y números (sin contar los guiones).");
  const idhex = limpio.slice(0, 16);
  const control = limpio.slice(16);
  const esperado = bytesAHex(await sha256("oqb-codigo:" + idhex)).slice(0, 2);
  if (control !== esperado) throw new Error("El código no coincide: revisa que esté bien copiado.");
  return idhex;
}

export async function codigoDe(idhex) {
  const control = bytesAHex(await sha256("oqb-codigo:" + idhex)).slice(0, 2);
  const g = (idhex + control).toUpperCase();
  return [g.slice(0, 4), g.slice(4, 8), g.slice(8, 12), g.slice(12, 16), g.slice(16)].join("-");
}

export async function archivoDe(idhex) {
  return bytesAHex(await sha256("oqb-cliente-archivo:" + idhex)).slice(0, 32);
}

async function claveNombre(idhex) {
  const k = (await sha256("oqb-cliente-nombre:" + idhex)).slice(0, 16);
  return crypto.subtle.importKey("raw", k, "AES-CTR", false, ["encrypt", "decrypt"]);
}

export function mensaje(idhex, nombre, fecha) {
  return te.encode("OQB-CLIENTE-1\n" + idhex + "\n" + nombre + "\n" + fecha);
}

// ed: el modulo @noble/ed25519 ya cargado. semilla: 32 bytes.
export async function emitir(ed, semilla, idhex, nombre, fecha) {
  // Contador: 8 bytes al azar + 8 en cero, que son los que avanzan. Asi el
  // incremento es el mismo en la app (libnx) y aqui (WebCrypto, length 64).
  const iv = new Uint8Array(16);
  crypto.getRandomValues(iv.subarray(0, 8));
  const cifrado = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-CTR", counter: iv, length: 64 }, await claveNombre(idhex), te.encode(nombre)),
  );
  const firma = await ed.signAsync(mensaje(idhex, nombre, fecha), semilla);
  return { v: 1, f: fecha, iv: bytesABase64(iv), n: bytesABase64(cifrado), s: bytesABase64(firma) };
}

// Devuelve el nombre si el certificado es valido para esa consola, o null.
export async function verificar(ed, idhex, cert) {
  try {
    const iv = base64ABytes(cert.iv);
    const plano = await crypto.subtle.decrypt({ name: "AES-CTR", counter: iv, length: 64 }, await claveNombre(idhex), base64ABytes(cert.n));
    const nombre = td.decode(plano);
    const ok = await ed.verifyAsync(base64ABytes(cert.s), mensaje(idhex, nombre, cert.f), hexABytes(CLAVE_PUBLICA_HEX));
    return ok ? nombre : null;
  } catch (e) {
    return null;
  }
}

// La firma del codigo de soporte: la consola manda su id, el nombre y la fecha
// en claro, mas la firma del certificado. Basta la clave publica.
export async function verificarSoporte(ed, datos) {
  try {
    return await ed.verifyAsync(base64ABytes(datos.s), mensaje(datos.id, datos.n, datos.f), hexABytes(CLAVE_PUBLICA_HEX));
  } catch (e) {
    return false;
  }
}
