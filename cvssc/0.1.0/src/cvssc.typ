#let cvssc = plugin("cvssc.wasm")

#let fix(dict) = {
  dict.pairs().fold((:), (db, it) => {
    let (k, v) = it
    k = k.clusters().fold("", (s, it) => {
      if it.match(regex("[A-Z]")) != none {
        return s + "-" + lower(it)
      } else {
        return s + it
      }
    })
    if type(v) == "float" { v = calc.round(v, digits: 2) }
    return db + ((k): v)
  })
}

// #let version(vector) = {
//   let valid = calculators.keys()
//   let re = regex("CVSS:([0-9.]+)")
//   let match = vector.match(re)
//   let result = match.at("captures", default: ("4.0",)).at(0)
//   // valid.at(result, default: "Invalid version " + str(result) + " [2.0, 3.0, 3.1, 4.0]")
//   if valid.contains(result) {
//     result
//   } else {
//     "Invalid version " + str(result) + " [2.0, 3.0, 3.1, 4.0]"
//   }
// }

// #let vec2str(..args) = {
//   args.named().pairs().map(it => {
//     let (k, v) = it
//     k + ":" + v
//   }).join("/")
// }

#let v2(vec) = {
  let result = fix(cbor.decode(cvssc.v2(bytes(vec))))
  if result.base-score < 4.0 {
    result.base-severity = "LOW"
  } else if result.base-score < 7.0 {
    result.base-severity = "MEDIUM"
  } else {
    result.base-severity = "HIGH"
  }
  result
}
#let v3(vec) = fix(cbor.decode(cvssc.v3(bytes(vec))))
#let v4(vec) = fix(cbor.decode(cvssc.v4(bytes(vec))))

// #v2("CVSS:2.0/AV:L/AC:L/Au:N/C:C/I:C/A:C")
// #v3("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
// #v4("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")