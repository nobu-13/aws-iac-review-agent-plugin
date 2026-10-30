# Phase 2 M1 — Publication File Manifest（Pre-Commit 監査）

> **Pre-Commit Remediation の注記（後から追加）**: 本書は Remediation の前の監査記録である。C-1〜C-3 の適用結果、最終の Hash、Commit 候補の一覧は `remediation-report.md` を参照する。

* Source: `git ls-files -co --exclude-standard`、`git ls-files -m`、`git diff .gitignore`、固定 Manifest（`.agents/tasks/phase2-m1-wp5/frozen-gate-attempt4/manifest.txt`、SHA-256 `360d731b5b10a30e231bbf01ae76b50055698c7ab9bf15d934ec042bba18aec5`、Git 管理外）
* 目的: Commit の候補になるファイルを1件ずつ列挙し、公開してはいけないものが含まれないことを確認する
* 状態: 監査のみ。Git Add、Commit はしていない。HEAD `4bd6e015d88b01d34dc83dc2b2d2ffb0058358b2`

## 1. 3つのファイル集合の差（監査対象 1）

3つの数は、同じ `git ls-files -co --exclude-standard`（tracked 633 と、ignore されない untracked）を、別の時点・別の除外で数えた値である。

| 集合 | 件数 | 定義 | 時点 |
| --- | --- | --- | --- |
| 固定 Manifest | 703 | 上記から `docs/v2/phase2/m1/wp5/*.md` を除いたもの | Final Frozen Gate attempt 4 の開始時 |
| Clean Checkout | 706 | 除外なし | Gate 12（attempt 4）の実行時 |
| Public Preflight | 711 | 除外なし（Preflight の `enumeration`） | WP5 文書をすべて書いた後の再実行 |

### 703 → 706（+3）

固定時にすでに存在した WP5 文書3件。固定範囲からは除外したが、Clean Checkout は除外せずに複写した。

* `docs/v2/phase2/m1/wp5/github-e2e-verification-plan.md`
* `docs/v2/phase2/m1/wp5/m1-known-limitations.md`
* `docs/v2/phase2/m1/wp5/oss-quickstart.md`

根拠: 固定時に保存した `git-status.txt`（同じ Directory）に、この3件が `??` で載っている。Gate 8（Preflight）も同じ時点で 706 files と報告した。

### 706 → 711（+5）

Gate の後に作成した WP5 文書5件。

* `docs/v2/phase2/m1/wp5/m1-final-ac-matrix.md`
* `docs/v2/phase2/m1/wp5/m1-integration-test-results.md`
* `docs/v2/phase2/m1/wp5/m1-reproducibility-report.md`
* `docs/v2/phase2/m1/wp5/m1-security-regression.md`
* `docs/v2/phase2/m1/wp5/wp5-acceptance-report.md`

### 除外・欠落

* 711 − 703 = 8 は、すべて `docs/v2/phase2/m1/wp5/*.md`。固定 Manifest にあって現在ないファイルは 0件（`comm` で確認）
* 監査時点（本監査の文書を作る前）で、同じ除外の Manifest を再計算すると `360d731b…18aec5` で、固定時と一致した
* 本監査の文書（`docs/v2/phase2/m1/precommit/` の5件）は、作成後に候補集合へ加わる（716 件になる見込み、§3）。固定 Manifest の照合では、この Directory も除外する必要がある
* `m1-known-limitations.md` と `m1-security-regression.md` は、Gate の後にも記述を直している（Mutant 数 22 → 29 など）。どちらも固定範囲の外で、Source、Fixture、Definition、生成 JSON ではない

## 2. Commit の候補（監査対象 2）

### 2-1. 変更される tracked ファイル

| Path | 変更 | SHA-256 |
| --- | --- | --- |
| `.gitignore` | 5行追加（`.agents/` と説明コメント）。削除行なし | `25bd42119aa09e5130eb77985bd6581bcef95abb4e1482e5201c4dd08c4efe4f` |

他の tracked 632 ファイルは変更なし（`git ls-files -m` は `.gitignore` だけ）。

### 2-2. 新しく追加される untracked ファイル（78件）

| # | Path | 区分 | Bytes | SHA-256 | 固定 Manifest |
| --- | --- | --- | --- | --- | --- |
| 1 | `.github/scripts/public_preflight.py` | Script（Hygiene） | 12340 | `70ccd44f100021afce9885ea91f28c9fb0b08bee5d00be2ee4c169edd4756406` | 含む |
| 2 | `docs/v2/phase2/m1/wp0/acceptance-alignment-audit.md` | 文書 | 18120 | `911317ea2138e5f9d666a9901544d460b55f8f298ed9c1e7bede02b0ce6ed1f3` | 含む |
| 3 | `docs/v2/phase2/m1/wp0/helper-audit.md` | 文書 | 19064 | `b5da5fa54613761e6823bcf06128a50619a9044ef3a42da388726d4ad5ce547a` | 含む |
| 4 | `docs/v2/phase2/m1/wp0/m1-acceptance-test-matrix.md` | 文書 | 17378 | `80c111832cdbabb7b190744bf984fe7d4277046b2d216e390c5f165bb50235ae` | 含む |
| 5 | `docs/v2/phase2/m1/wp0/m1-architecture-proposal.md` | 文書 | 24407 | `afd3a97158755e3eb9d383774cfeed238e9c6605c633a1ec5284717744731b0e` | 含む |
| 6 | `docs/v2/phase2/m1/wp0/repository-baseline.md` | 文書 | 10670 | `bb44137d1611d0ecf49729ab32f3b39ab4d96a49b214acf7ab139c362f5e029e` | 含む |
| 7 | `docs/v2/phase2/m1/wp1/wp1-acceptance-report.md` | 文書 | 10533 | `7a6d29943da6c2773650dd4a3569f93967d87f00657cafe29cbf5e1fd3bd07c4` | 含む |
| 8 | `docs/v2/phase2/m1/wp1/wp1-architecture-note.md` | 文書 | 12020 | `a0ecad7717228df60b8114fbe29d2ac5d70079e5d8c2a30689c11a9d13519877` | 含む |
| 9 | `docs/v2/phase2/m1/wp2/wp2-acceptance-report.md` | 文書 | 11712 | `d0ae21391197ed9694846b4b960df5f8a87d908f9f8443474f4825e1b7c6ebf3` | 含む |
| 10 | `docs/v2/phase2/m1/wp2/wp2-architecture-note.md` | 文書 | 14900 | `b027e7878be7fd138e381ddc24125eb7e16bd30cccd00828fd29866dee62453b` | 含む |
| 11 | `docs/v2/phase2/m1/wp3/raw-evidence-security-policy.md` | 文書 | 7054 | `adea3e540ef760e763371bdf323d628ef048221cf9faab6122b4c82e93ce2b0b` | 含む |
| 12 | `docs/v2/phase2/m1/wp3/wp3-acceptance-report.md` | 文書 | 9889 | `7bb18f58d9d012ce587e438652722b6e17a54a7fede6f685572459e5bf179084` | 含む |
| 13 | `docs/v2/phase2/m1/wp3/wp3-architecture-note.md` | 文書 | 15516 | `145f3d025e5a7b3a14564f34a91b9601f6cbc4bfdda02f19b259e5402ed27fb1` | 含む |
| 14 | `docs/v2/phase2/m1/wp4/evaluator-rule-coverage.md` | 文書 | 10358 | `ec637a28f2011a0a0c7bc8383be2226a98e292b99d465eabdd3055198867fe54` | 含む |
| 15 | `docs/v2/phase2/m1/wp4/legacy-reevaluation-differences.md` | 文書 | 7583 | `8bbafaa5fdb4752436d778abc8c7576dd2fc308015ea7a259646df6150920493` | 含む |
| 16 | `docs/v2/phase2/m1/wp4/legacy-reevaluation-results.json` | 生成 Evidence（Legacy 再評価結果） | 88410 | `b17e6881d20e27987da62716595629212afcdcf0529d9f313e26474a29f7d544` | 含む |
| 17 | `docs/v2/phase2/m1/wp4/mutation-test-results.md` | 文書 | 5962 | `ec8be0c22e73afe37fbfabaa39084e2bcb6a98ce8f591a1d1a21f1a2af73f2f4` | 含む |
| 18 | `docs/v2/phase2/m1/wp4/replay-reproducibility-report.md` | 文書 | 5506 | `666f078109d855e64ec898729bf4fb83190eea6ff3c094706eb13126e7d089b5` | 含む |
| 19 | `docs/v2/phase2/m1/wp4/wp4-acceptance-report.md` | 文書 | 7518 | `3a4ef9e863b95f016022bd1226bffb6446a34d79b8a09950e94a4bdf1e6e95ce` | 含む |
| 20 | `docs/v2/phase2/m1/wp4/wp4-architecture-note.md` | 文書 | 9666 | `866ca2289fc91339268b75499d442dd4acc1010529c5a5e55f1f0a3f2bea0aa8` | 含む |
| 21 | `docs/v2/phase2/m1/wp5/github-e2e-verification-plan.md` | 文書 | 9204 | `9e26209769ab664b98f79dbc2bb44642a136238625ff9acf26063cb38bf6b94a` | 含まない（Gate 後に作成・更新した WP5 文書） |
| 22 | `docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json` | 生成 Evidence（Legacy 再評価結果） | 112316 | `f205b5d4e9b1d8b91c8c35869dec7972d918215cefebbdc17d24590ad9bb70ed` | 含む |
| 23 | `docs/v2/phase2/m1/wp5/m1-final-ac-matrix.md` | 文書 | 17246 | `8fa65265897a633a94ce48aaac2a21c56127a9b990aae3fdb9c697f1d01502d7` | 含まない（Gate 後に作成・更新した WP5 文書） |
| 24 | `docs/v2/phase2/m1/wp5/m1-integration-test-results.md` | 文書 | 5706 | `ab1c74299b3511a84b11f004eb47f5ad8cc16dbc9e5eed455dea479a92a90570` | 含まない（Gate 後に作成・更新した WP5 文書） |
| 25 | `docs/v2/phase2/m1/wp5/m1-known-limitations.md` | 文書 | 4977 | `004e9478c915c03b75226acfbcadf6a9454d991ad1184a3291903e391334a6ca` | 含まない（Gate 後に作成・更新した WP5 文書） |
| 26 | `docs/v2/phase2/m1/wp5/m1-reproducibility-report.md` | 文書 | 7229 | `d4abf27fc30f7ab01be87e625b4b1c97e868d44945f1eceba2025844c10b7152` | 含まない（Gate 後に作成・更新した WP5 文書） |
| 27 | `docs/v2/phase2/m1/wp5/m1-security-regression.md` | 文書 | 11413 | `5c46d9fa7aff62308614f45c3c68d7a7d7a9538fa97cc5821225e7146012292e` | 含まない（Gate 後に作成・更新した WP5 文書） |
| 28 | `docs/v2/phase2/m1/wp5/oss-quickstart.md` | 文書 | 6511 | `70c512e9c70fa842dad71f2203d38e6787629c4ec424a15698d5862e562a9e40` | 含まない（Gate 後に作成・更新した WP5 文書） |
| 29 | `docs/v2/phase2/m1/wp5/wp5-acceptance-report.md` | 文書 | 20151 | `b9cda0cd9b4a1ef74f3a6327fb549bd60ed5b7d4b2fece126f538779e4d66be1` | 含まない（Gate 後に作成・更新した WP5 文書） |
| 30 | `iacreview/evidence/__init__.py` | Source（製品） | 989 | `6cfc743a2c047ecc5eeaca13edd9b9696537afbc565b1eb77ea52f5171ba45cc` | 含む |
| 31 | `iacreview/evidence/artifact.py` | Source（製品） | 14623 | `1ef926e000e6826d75a9fb31ec0f33ededce0858059c0b6f4c72bc295cd05b58` | 含む |
| 32 | `iacreview/evidence/canonical.py` | Source（製品） | 3125 | `91959db95fb2a5e06aeb3c3355ad2d76b8e15bd13b4cb233ee678a679eb46c89` | 含む |
| 33 | `iacreview/evidence/collector.py` | Source（製品） | 15398 | `84d751fcacf318998cbae500532ee4590a773ef995c6ba7c445e4515e30589fe` | 含む |
| 34 | `iacreview/evidence/definitions/phase1-app-demo-s7.v1.json` | データ（製品） | 75149 | `efd934b0badd8cbdc50ec13fcc0be4dec0e501ad26bf0507f546dd6d36e28589` | 含む |
| 35 | `iacreview/evidence/envelope.py` | Source（製品） | 12502 | `774332eb6530f392072467e36d021282904457280945a52541fdfc560fa8bc9a` | 含む |
| 36 | `iacreview/evidence/evaluator.py` | Source（製品） | 17309 | `68bb38b3bd08b5c173f572387243bbbc5f5968172efb92f755a783878349e85d` | 含む |
| 37 | `iacreview/evidence/facts.py` | Source（製品） | 16595 | `662fb5e12896679e9da862e6ddcf27dc7ae5cb324813fbd82d49c71425f5b865` | 含む |
| 38 | `iacreview/evidence/final_report.py` | Source（製品） | 5043 | `6be7e135fe35cfef1ff9aa1c3ff29b458c3a6345377df0cd85e52ee1c17a8135` | 含む |
| 39 | `iacreview/evidence/integrity.py` | Source（製品） | 13774 | `9165fb42282a0ffc20c670cd825f4074a03cc646801598ccc2efbec25cefce23` | 含む |
| 40 | `iacreview/evidence/legacy.py` | Source（製品） | 15107 | `8e2a1c985676fd294a567be86483a79850263283488f5f436529f148e3424d07` | 含む |
| 41 | `iacreview/evidence/legacy/phase1-legacy-evidence-map.v1.json` | データ（製品） | 102233 | `d0bd9342441234fc18246269ef16948a883fc8f6fa56e85ee105c3666c97df15` | 含む |
| 42 | `iacreview/evidence/legacy_reeval.py` | Source（製品） | 3059 | `3e55213d7df867f7c9dd86b1bac07d5bf26b5d204a65077a8c9c8be0449785f9` | 含む |
| 43 | `iacreview/evidence/open_questions.py` | Source（製品） | 10397 | `479025967e8f11ade944ca6e91dd6d9500ada5ea1ba36c7b1d34f65e014c49ba` | 含む |
| 44 | `iacreview/evidence/registry.py` | Source（製品） | 42693 | `3f91ec26477b7a78f10bed5891f0829d95f2c58b537ebf1e37ae550dbcd6c7ef` | 含む |
| 45 | `iacreview/evidence/replay.py` | Source（製品） | 5860 | `141f81872df0012dd7771f58f34fc090af771fd9f1787fbe9f7ae4a48008e89c` | 含む |
| 46 | `iacreview/evidence/rule_s7_evidence.py` | Source（製品） | 3581 | `5d22859401aa235398c141c67e054df722ec403dfba772ccb2c378b060c0215f` | 含む |
| 47 | `iacreview/evidence/rules.py` | Source（製品） | 7342 | `f8a553fcb4fc9678c3b1725e27cf95b5306cab34e237aa0f9905e03dfbdb5bee` | 含む |
| 48 | `iacreview/evidence/rules_s7.py` | Source（製品） | 24596 | `83f79417d9c0a902c45bf9818edf820af23a85e7fe23dc812305f21b8af6c626` | 含む |
| 49 | `iacreview/evidence/schema/acceptance-definition.v1.schema.json` | データ（製品） | 17236 | `25e6e70f2e9e89af9a826b58ffbc293e3c612589f5fba0e32f44dab221ec8e33` | 含む |
| 50 | `iacreview/evidence/secretgate.py` | Source（製品） | 8299 | `a688c6ceb0e63aae681cc1bb7dbfe2c27c9217f205bb15f65091c1b8206479a9` | 含む |
| 51 | `iacreview/evidence/snapshot.py` | Source（製品） | 6782 | `88cb0cbbabb468dac62baacb0b45dbdbea9ef441517f7477a9c3e4267364ffbd` | 含む |
| 52 | `iacreview/evidence/store.py` | Source（製品） | 39886 | `4c95194da7cb9bf8fdb68f6f4e27a821419e3a3904c98b1cd34ef452aff9e8a6` | 含む |
| 53 | `tests/fixtures/evidence_raw/job_log_masked_header.json` | Fixture（合成） | 190 | `ff38a66c8b0354b4142e291f215c1b1447718070afc4d955380ae2e4e8c1fb83` | 含む |
| 54 | `tests/fixtures/evidence_raw/rest_check_runs_safe.json` | Fixture（合成） | 830 | `490b17fb69471acde2e40c0792eb3727865955b55a2674500a9a23323064e1bf` | 含む |
| 55 | `tests/fixtures/evidence_raw/rest_commit_with_email.json` | Fixture（合成） | 373 | `3fd6bb14b63cb75d23f173391146000925d348797ff0b206845240c07309424f` | 含む |
| 56 | `tests/fixtures/evidence_raw/rest_http_error_404.json` | Fixture（合成） | 103 | `109ea3ac03f05fd95fb980e8f76b8e113bb9bd96363cf43df433240355938556` | 含む |
| 57 | `tests/fixtures/evidence_raw/rest_installation_non_secret_urls.json` | Fixture（合成） | 446 | `efdd98b3174ccf5998105b40e442c0c27276d2eec79a6923ba46d0366e9a548c` | 含む |
| 58 | `tests/fixtures/evidence_raw/rest_noreply_email.json` | Fixture（合成） | 137 | `3ed2a666b70dde50f9cbef1194211573b7535b3d8cd0ff9a14f88b6409037c3f` | 含む |
| 59 | `tests/fixtures/evidence_raw/rest_pulls_page1.json` | Fixture（合成） | 249 | `096d89518389ea6198c23cf3229d2eeab6b6b8d0d91840528a0e33916b936fbe` | 含む |
| 60 | `tests/fixtures/evidence_raw/rest_pulls_page2.json` | Fixture（合成） | 126 | `5017a700933e8452b676ed732712f3937b0f2d401b856a929a077278fb97ae3e` | 含む |
| 61 | `tests/mutation/evidence_mutants.py` | Test | 21997 | `dc461e7bb3952f7011e63d3ea2cdf6d2aa2f3855e8134ad115b5fb139fbef51c` | 含む |
| 62 | `tests/unit/evidence_synth.py` | Test | 14804 | `d5b4e6d96fe7e08cb1754191962684ba3412d0968f78549d52ca20e5f9fdea5f` | 含む |
| 63 | `tests/unit/test_evidence_artifact.py` | Test | 12037 | `70d55a427bcf5e67c76fb082a31a8ba575faf2eb89b47e3d44b76b98a728be8a` | 含む |
| 64 | `tests/unit/test_evidence_collector.py` | Test | 10548 | `5e6f785183e0888251203a0787a8b05886c4e40177ab0a3d5ac23dbcfdff08eb` | 含む |
| 65 | `tests/unit/test_evidence_evaluator_s7.py` | Test | 13139 | `53899eee96b4afc9b267990c473dda36151106e20379e78e0cd83ea41d489cba` | 含む |
| 66 | `tests/unit/test_evidence_integrity.py` | Test | 18120 | `01b77358e8e47783ff15bd33d19827d6ea7a388cf3f196a59a577caed7fcb82f` | 含む |
| 67 | `tests/unit/test_evidence_legacy.py` | Test | 8316 | `f43fba5f2b0b470c575891c4eb84ace474499a9173b882888ec0bd6264f236b9` | 含む |
| 68 | `tests/unit/test_evidence_legacy_reeval.py` | Test | 8081 | `dcee1cb15722261db08a306183b24aac89dd71b37c323be3831a5dc1db42ffd2` | 含む |
| 69 | `tests/unit/test_evidence_mutations.py` | Test | 1967 | `c5ef6986a794db678e34f162309fc64e21806da829233914b6268a6ae900c96e` | 含む |
| 70 | `tests/unit/test_evidence_pipeline.py` | Test | 12924 | `f5a3bc5243bfe3780c7003ad07fe7392692ae1371d9151857ac58a9f014c67f3` | 含む |
| 71 | `tests/unit/test_evidence_preflight.py` | Test | 9315 | `4bb28c019348f7353807637a613ae950e90bd5d30020043ff369b87300688fd6` | 含む |
| 72 | `tests/unit/test_evidence_raw_policy.py` | Test | 5787 | `4845f56358da037e28d5056c328cf47c8638036f00f233ce2c6effa97bdc5571` | 含む |
| 73 | `tests/unit/test_evidence_registry.py` | Test | 19193 | `a6a70fd768ad00b291e6e3b828ba93d5a576d4b584f0dc79714ab0f645aca585` | 含む |
| 74 | `tests/unit/test_evidence_replay.py` | Test | 10805 | `ee68a6a2ca0cce129342d76b09030d6a3ca3e8706ab5496f6175a1872e8257b5` | 含む |
| 75 | `tests/unit/test_evidence_report.py` | Test | 8981 | `738c922419e8e12fefad52be9e123fcfbb5d6514e7db11164c43a476915a2f75` | 含む |
| 76 | `tests/unit/test_evidence_s7_definition.py` | Test | 6628 | `1f15cad832ce329b78b20b271992b6eb2b822755ee4aacc40de81249679a2463` | 含む |
| 77 | `tests/unit/test_evidence_secretgate.py` | Test | 8347 | `b80e76e1b2cc6ebf65fa34580ca235825adad6bcc9ccc8b2da9be1aa9ec939ee` | 含む |
| 78 | `tests/unit/test_evidence_store.py` | Test | 21961 | `4244d011ae8c6916ef82b055bf934e550326cbe47df5eff4fae6b3550ca30a2e` | 含む |

内訳: Source（製品）20、データ（製品）3、Test 18、Fixture（合成）8、Script 1、文書 26、生成 Evidence 2（合計78）。

### 2-3. 本監査で追加する文書（5件、§1 の最後を参照）

* `docs/v2/phase2/m1/precommit/precommit-audit.md`
* `docs/v2/phase2/m1/precommit/publication-file-manifest.md`
* `docs/v2/phase2/m1/precommit/s7-19-interpretation-review.md`
* `docs/v2/phase2/m1/precommit/definition-versioning-policy.md`
* `docs/v2/phase2/m1/precommit/precommit-decision.md`

## 3. 含まれてはいけないものの確認

対象: §2-2 の78件と `.gitignore`。

| 確認 | 方法 | 結果 |
| --- | --- | --- |
| `.agents/`、`.kiro/` 配下 | Path の検査、`git ls-files .agents .kiro` | 0件。`.agents/` は `.gitignore` で除外、`.kiro/` も ignore 済み（Preflight `no_tracked_private_path` PASS） |
| 個人 Targets（`*targets.json`） | Path の検査 | 0件 |
| PEM、Key、`.env`、credentials | Path の検査、`BEGIN … PRIVATE KEY` の内容検索 | 0件 |
| Token の形（`gh?_…`、`AKIA…`） | 内容検索 | 0件。`github_pat_` は4件にあるが、いずれも規則名・説明の文字列で値ではない（`secretgate.py` の正規表現、WP0 文書3件の説明） |
| 実 Raw Evidence | Fixture の内容確認 | `tests/fixtures/evidence_raw/` の8件はすべて合成値（`synthetic-owner`、`example.invalid`、`aaaa…` SHA、App id `1000001`）。Phase 1 の Raw は含まない |
| ローカルログ（`*.log`）、coverage、`__pycache__` | Path の検査 | 0件 |
| ネストした `.git`、Symbolic Link | `find` | 0件 |
| 実行 bit、CRLF、200 KB 超のファイル | `test -x`、CR の検索、`find -size` | 0件。合計 1.3 MB |
| Secret Scan / Public Preflight | `scan_secrets.py`（tracked mode）、`public_preflight.py` | 0 finding / PASS（WP5、711 files） |

### 3-1. 秘密ではないが、公開前に Human 判断が要る識別子

| ID | 内容 | 場所 | 評価 |
| --- | --- | --- | --- |
| PC-1 | GitHub Account 名（本書では値を書かない） | `docs/v2/phase2/m1/wp0/repository-baseline.md` L51、`docs/v2/phase2/m1/wp0/m1-acceptance-test-matrix.md` L27 | 監査記述の中の例示。同じ名前は tracked の `iacreview/sarif.py` L215（この Repository の公開 URL）にすでにある。ただし WP0 はこれを「PII 相当の識別子」と分類し、M1-01 の異常系①に挙げている |
| PC-2 | Phase 1 で使った GitHub App の実際の App id（7桁） | `docs/v2/phase2/m1/wp0/acceptance-alignment-audit.md` L58、`tests/unit/test_evidence_secretgate.py` L163 | Secret ではない。ただし Test の値は「合成」と説明している中に実在の id が混ざっている。WP5 の Clean Checkout の検索語に App id を入れていなかったため、WP5 の報告では見落とした |
| PC-3 | Phase 1 Demo Repository の Commit SHA、Actions Run id、`.agents/` 配下の Path | `iacreview/evidence/legacy/phase1-legacy-evidence-map.v1.json`（`.agents/` の Path 135件、Run id を含む File 名）、`docs/v2/phase2/m1/wp5/wp5-acceptance-report.md` §4-2 | Traceability のための Locator で、Secret ではない。Demo Repository の名前は含まない（検索0件） |

PC-1〜PC-3 は Secret Scan と Preflight の規則では検出されない。公開してよいかは Human が決める（`precommit-decision.md`）。
