// Вспомогательное (имя с "_" Pages не считает маршрутом).
export function hex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}
