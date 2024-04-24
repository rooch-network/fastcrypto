(function() {var type_impls = {
"fastcrypto_tbls":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-ThresholdBls-for-ThresholdBls12381MinSig\" class=\"impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/types.rs.html#16-32\">source</a><a href=\"#impl-ThresholdBls-for-ThresholdBls12381MinSig\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html\" title=\"trait fastcrypto_tbls::tbls::ThresholdBls\">ThresholdBls</a> for <a class=\"struct\" href=\"fastcrypto_tbls/types/struct.ThresholdBls12381MinSig.html\" title=\"struct fastcrypto_tbls::types::ThresholdBls12381MinSig\">ThresholdBls12381MinSig</a></h3></section></summary><div class=\"impl-items\"><section id=\"associatedtype.Private\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Private\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Private\" class=\"associatedtype\">Private</a> = Scalar</h4></section><details class=\"toggle\" open><summary><section id=\"associatedtype.Public\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Public\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Public\" class=\"associatedtype\">Public</a> = G2Element</h4></section></summary><div class='docblock'><code>Public</code> represents the group over which the public keys are represented.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.Signature\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Signature\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Signature\" class=\"associatedtype\">Signature</a> = G1Element</h4></section></summary><div class='docblock'><code>Signature</code> represents the group over which the signatures are represented.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.verify\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/types.rs.html#21-31\">source</a><a href=\"#method.verify\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#tymethod.verify\" class=\"fn\">verify</a>(\n    pk: &amp;Self::<a class=\"associatedtype\" href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Public\" title=\"type fastcrypto_tbls::tbls::ThresholdBls::Public\">Public</a>,\n    msg: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/std/primitive.u8.html\">u8</a>],\n    sig: &amp;Self::<a class=\"associatedtype\" href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Signature\" title=\"type fastcrypto_tbls::tbls::ThresholdBls::Signature\">Signature</a>\n) -&gt; FastCryptoResult&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/std/primitive.unit.html\">()</a>&gt;</h4></section></summary><div class='docblock'>Verify a signature on a given message. This is standard BLS signature verification\nover the used curve construction.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.partial_sign\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/tbls.rs.html#34-36\">source</a><a href=\"#method.partial_sign\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#method.partial_sign\" class=\"fn\">partial_sign</a>(\n    share: &amp;<a class=\"type\" href=\"fastcrypto_tbls/tbls/type.Share.html\" title=\"type fastcrypto_tbls::tbls::Share\">Share</a>&lt;Self::<a class=\"associatedtype\" href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Private\" title=\"type fastcrypto_tbls::tbls::ThresholdBls::Private\">Private</a>&gt;,\n    msg: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/std/primitive.u8.html\">u8</a>]\n) -&gt; <a class=\"type\" href=\"fastcrypto_tbls/tbls/type.PartialSignature.html\" title=\"type fastcrypto_tbls::tbls::PartialSignature\">PartialSignature</a>&lt;Self::<a class=\"associatedtype\" href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Signature\" title=\"type fastcrypto_tbls::tbls::ThresholdBls::Signature\">Signature</a>&gt;</h4></section></summary><div class='docblock'>Sign a message using the private share/partial key.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.partial_sign_batch\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/tbls.rs.html#39-53\">source</a><a href=\"#method.partial_sign_batch\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#method.partial_sign_batch\" class=\"fn\">partial_sign_batch</a>(\n    shares: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a>&lt;Item = impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/borrow/trait.Borrow.html\" title=\"trait core::borrow::Borrow\">Borrow</a>&lt;<a class=\"type\" href=\"fastcrypto_tbls/tbls/type.Share.html\" title=\"type fastcrypto_tbls::tbls::Share\">Share</a>&lt;Self::<a class=\"associatedtype\" href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Private\" title=\"type fastcrypto_tbls::tbls::ThresholdBls::Private\">Private</a>&gt;&gt;&gt;,\n    msg: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/std/primitive.u8.html\">u8</a>]\n) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/1.77.2/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"type\" href=\"fastcrypto_tbls/tbls/type.PartialSignature.html\" title=\"type fastcrypto_tbls::tbls::PartialSignature\">PartialSignature</a>&lt;Self::<a class=\"associatedtype\" href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Signature\" title=\"type fastcrypto_tbls::tbls::ThresholdBls::Signature\">Signature</a>&gt;&gt;</h4></section></summary><div class='docblock'>Sign a message using one of more private share/partial keys.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.partial_verify\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/tbls.rs.html#56-63\">source</a><a href=\"#method.partial_verify\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#method.partial_verify\" class=\"fn\">partial_verify</a>(\n    vss_pk: &amp;<a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;Self::<a class=\"associatedtype\" href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Public\" title=\"type fastcrypto_tbls::tbls::ThresholdBls::Public\">Public</a>&gt;,\n    msg: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/std/primitive.u8.html\">u8</a>],\n    partial_sig: &amp;<a class=\"type\" href=\"fastcrypto_tbls/tbls/type.PartialSignature.html\" title=\"type fastcrypto_tbls::tbls::PartialSignature\">PartialSignature</a>&lt;Self::<a class=\"associatedtype\" href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Signature\" title=\"type fastcrypto_tbls::tbls::ThresholdBls::Signature\">Signature</a>&gt;\n) -&gt; FastCryptoResult&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/std/primitive.unit.html\">()</a>&gt;</h4></section></summary><div class='docblock'>Verify a signature done by a partial key holder.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.partial_verify_batch\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/tbls.rs.html#68-91\">source</a><a href=\"#method.partial_verify_batch\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#method.partial_verify_batch\" class=\"fn\">partial_verify_batch</a>&lt;R: AllowedRng&gt;(\n    vss_pk: &amp;<a class=\"struct\" href=\"fastcrypto_tbls/polynomial/struct.Poly.html\" title=\"struct fastcrypto_tbls::polynomial::Poly\">Poly</a>&lt;Self::<a class=\"associatedtype\" href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Public\" title=\"type fastcrypto_tbls::tbls::ThresholdBls::Public\">Public</a>&gt;,\n    msg: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/std/primitive.u8.html\">u8</a>],\n    partial_sigs: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a>&lt;Item = impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/borrow/trait.Borrow.html\" title=\"trait core::borrow::Borrow\">Borrow</a>&lt;<a class=\"type\" href=\"fastcrypto_tbls/tbls/type.PartialSignature.html\" title=\"type fastcrypto_tbls::tbls::PartialSignature\">PartialSignature</a>&lt;Self::<a class=\"associatedtype\" href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Signature\" title=\"type fastcrypto_tbls::tbls::ThresholdBls::Signature\">Signature</a>&gt;&gt;&gt;,\n    rng: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/std/primitive.reference.html\">&amp;mut R</a>\n) -&gt; FastCryptoResult&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/std/primitive.unit.html\">()</a>&gt;</h4></section></summary><div class='docblock'>Verify a set of signatures done by a partial key holder.\nRandomly check if \\sum r_i sig_i is a valid signature with public key \\sum r_i p(i) G\nwhere r_i are random scalars, and p(i) are points on the polynomial.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.aggregate\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/fastcrypto_tbls/tbls.rs.html#96-109\">source</a><a href=\"#method.aggregate\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#method.aggregate\" class=\"fn\">aggregate</a>(\n    threshold: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.77.2/std/primitive.u16.html\">u16</a>,\n    partials: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/iter/traits/iterator/trait.Iterator.html\" title=\"trait core::iter::traits::iterator::Iterator\">Iterator</a>&lt;Item = impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/borrow/trait.Borrow.html\" title=\"trait core::borrow::Borrow\">Borrow</a>&lt;<a class=\"type\" href=\"fastcrypto_tbls/tbls/type.PartialSignature.html\" title=\"type fastcrypto_tbls::tbls::PartialSignature\">PartialSignature</a>&lt;Self::<a class=\"associatedtype\" href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Signature\" title=\"type fastcrypto_tbls::tbls::ThresholdBls::Signature\">Signature</a>&gt;&gt;&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.77.2/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>\n) -&gt; FastCryptoResult&lt;Self::<a class=\"associatedtype\" href=\"fastcrypto_tbls/tbls/trait.ThresholdBls.html#associatedtype.Signature\" title=\"type fastcrypto_tbls::tbls::ThresholdBls::Signature\">Signature</a>&gt;</h4></section></summary><div class='docblock'>Interpolate partial signatures to recover the full signature.\nUses the first <code>threshold</code> unique partials to interpolate the signature and the rest are\nignored (thus if those partials are invalid, the resulting signature can still be valid).</div></details></div></details>","ThresholdBls","fastcrypto_tbls::types::PrivateBlsKey","fastcrypto_tbls::types::PublicBlsKey","fastcrypto_tbls::types::Signature"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()