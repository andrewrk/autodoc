(function() {
    const CAT_namespace = 0;
    const CAT_global_variable = 1;
    const CAT_function = 2;
    const CAT_type = 3;
    const CAT_error_set = 4;
    const CAT_global_const = 5;
    const CAT_primitive_true = 6;
    const CAT_primitive_false = 7;
    const CAT_primitive_null = 8;
    const CAT_alias = 9;

    var domStatus = document.getElementById("status");
    var domSectNav = document.getElementById("sectNav");
    var domListNav = document.getElementById("listNav");
    var domSectTypes = document.getElementById("sectTypes");
    var domListTypes = document.getElementById("listTypes");
    var domSectNamespaces = document.getElementById("sectNamespaces");
    var domListNamespaces = document.getElementById("listNamespaces");
    var domSectErrSets = document.getElementById("sectErrSets");
    var domListErrSets = document.getElementById("listErrSets");
    var domSectFns = document.getElementById("sectFns");
    var domListFns = document.getElementById("listFns");
    var domSectFields = document.getElementById("sectFields");
    var domListFields = document.getElementById("listFields");
    var domSectGlobalVars = document.getElementById("sectGlobalVars");
    var domListGlobalVars = document.getElementById("listGlobalVars");
    var domSectValues = document.getElementById("sectValues");
    var domListValues = document.getElementById("listValues");
    var domFnProto = document.getElementById("fnProto");
    var domFnProtoCode = document.getElementById("fnProtoCode");
    var domFnDocs = document.getElementById("fnDocs");
    var domSectFnErrors = document.getElementById("sectFnErrors");
    var domListFnErrors = document.getElementById("listFnErrors");
    var domTableFnErrors = document.getElementById("tableFnErrors");
    var domFnErrorsAnyError = document.getElementById("fnErrorsAnyError");
    var domFnExamples = document.getElementById("fnExamples");
    var domFnNoExamples = document.getElementById("fnNoExamples");
    var domSearch = document.getElementById("search");
    var domSectSearchResults = document.getElementById("sectSearchResults");
    var domListSearchResults = document.getElementById("listSearchResults");
    var domSectSearchNoResults = document.getElementById("sectSearchNoResults");
    var domListInfo = document.getElementById("listInfo");
    var domHdrName = document.getElementById("hdrName");
    var domHelpModal = document.getElementById("helpDialog");

    var zigAnalysis = {
      typeKinds: [
        "Type","Void","Bool","NoReturn","Int","Float","Pointer","Array","Struct",
        "ComptimeFloat","ComptimeInt","Undefined","Null","Optional","ErrorUnion","ErrorSet","Enum",
        "Union","Fn","BoundFn","ArgTuple","Opaque","Frame","AnyFrame","Vector","EnumLiteral"
      ],
      params: {
        zigVersion: "0.12.0-dev.3083+9410b11ca",
        builds: ["universal"],
        rootName: "std",
      },
      calls: [],
      types: [
        {kind: 0, name: "type"},
      ],
      decls: [],
      fns: [],
      errors: [],
      astNodes: [],
      files: [],
    };

    var searchTimer = null;
    var escapeHtmlReplacements = { "&": "&amp;", '"': "&quot;", "<": "&lt;", ">": "&gt;" };

    var typeKinds = indexTypeKinds();

    const curNav = {
      // 0 = home
      // 1 = decl
      tag: 0,
      // unsigned int: decl index
      decl: null,
    };
    var curNavSearch = "";
    var curSearchIndex = -1;
    var imFeelingLucky = false;

    // names of packages in the same order as wasm
    const packageList = [];

    let wasm_promise = fetch("main.wasm");
    let sources_promise = fetch("sources.tar").then(function(response) {
      if (!response.ok) throw new Error("unable to download sources");
      return response.arrayBuffer();
    });
    var wasm_exports = null;

    const text_decoder = new TextDecoder();
    const text_encoder = new TextEncoder();

    WebAssembly.instantiateStreaming(wasm_promise, {
      js: {
        log: function(ptr, len) {
          const msg = decodeString(ptr, len);
          console.log(msg);
        },
        panic: function (ptr, len) {
            const msg = decodeString(ptr, len);
            throw new Error("panic: " + msg);
        },
      },
    }).then(function(obj) {
      wasm_exports = obj.instance.exports;
      window.wasm = obj; // for debugging

      sources_promise.then(function(buffer) {
        const js_array = new Uint8Array(buffer);
        const ptr = wasm_exports.alloc(js_array.length);
        const wasm_array = new Uint8Array(wasm_exports.memory.buffer, ptr, js_array.length);
        wasm_array.set(js_array);
        wasm_exports.unpack(ptr, js_array.length);

        updatePackageList();

        window.addEventListener('hashchange', onHashChange, false);
        domSearch.addEventListener('keydown', onSearchKeyDown, false);
        window.addEventListener('keydown', onWindowKeyDown, false);
        onHashChange();
      });
    });

    function renderTitle() {
      const suffix = "- Zig Documentation";
      if (curNav.decl == null) {
        document.title = packageList[0] + suffix; // Home
      } else {
        document.title = fullyQualifiedName(curNav.decl) + suffix;
      }
    }

    function render() {
        domStatus.classList.add("hidden");
        domFnProto.classList.add("hidden");
        domFnDocs.classList.add("hidden");
        domSectTypes.classList.add("hidden");
        domSectNamespaces.classList.add("hidden");
        domSectErrSets.classList.add("hidden");
        domSectFns.classList.add("hidden");
        domSectFields.classList.add("hidden");
        domSectSearchResults.classList.add("hidden");
        domSectSearchNoResults.classList.add("hidden");
        domHdrName.classList.add("hidden");
        domSectNav.classList.add("hidden");
        domSectFnErrors.classList.add("hidden");
        domFnExamples.classList.add("hidden");
        domFnNoExamples.classList.add("hidden");
        domFnErrorsAnyError.classList.add("hidden");
        domTableFnErrors.classList.add("hidden");
        domSectGlobalVars.classList.add("hidden");
        domSectValues.classList.add("hidden");

        renderTitle();

        if (curNavSearch !== "") return renderSearch();

        switch (curNav.tag) {
          case 0: return renderHome();
          case 1:
            if (curNav.decl == null) {
              return render404();
            } else {
              return renderDecl(curNav.decl);
            }
          default: throw new Error("invalid navigation state");
        }
    }

    function renderHome() {
      if (packageList.length == 1) return renderPackage(0);

      domStatus.textContent = "TODO implement renderHome for multiple packages";
      domStatus.classList.remove("hidden");
    }

    function renderPackage(pkg_index) {
      const root_decl = wasm_exports.find_package_root(pkg_index);
      return renderDecl(root_decl);
    }

    function renderDecl(decl_index) {
      const category = wasm_exports.categorize_decl(decl_index);
      switch (category) {
        case CAT_namespace: return renderNamespace(decl_index);
        case CAT_global_variable: throw new Error("TODO: CAT_GLOBAL_VARIABLE");
        case CAT_function: throw new Error("TODO: CAT_FUNCTION");
        case CAT_type: throw new Error("TODO CAT_type");
        case CAT_error_set: throw new Error("TODO CAT_error_set");
        case CAT_global_const: throw new Error("TODO CAT_global_const");
        case CAT_primitive_true: throw new Error("TODO primitive value");
        case CAT_primitive_false: throw new Error("TODO primitive value");
        case CAT_primitive_null: throw new Error("TODO primitive value");
        case CAT_alias: return renderDecl(wasm_exports.get_aliasee());
        default: throw new Error("unrecognized category " + category);
      }
    }

    function renderNav() {
      const list = [];
      {
        let decl_it = curNav.decl;
        while (decl_it) {
          list.push({
            name: declIndexName(decl_it),
            href: navLinkDeclIndex(decl_it),
          });
          decl_it = declParent(decl_it);
        }
        list.reverse();
      }
      resizeDomList(domListNav, list.length, '<li><a href="#"></a></li>');

      for (let i = 0; i < list.length; i += 1) {
          const liDom = domListNav.children[i];
          const aDom = liDom.children[0];
          aDom.textContent = list[i].name;
          aDom.setAttribute('href', list[i].href);
          if (i + 1 == list.length) {
              aDom.classList.add("active");
          } else {
              aDom.classList.remove("active");
          }
      }

      domSectNav.classList.remove("hidden");
    }

    function render404() {
        domStatus.textContent = "404 Not Found";
        domStatus.classList.remove("hidden");
    }

    function navLinkFqn(full_name) {
      return '#' + full_name;
    }

    function navLink(pkgNames, declNames) {
        if (pkgNames.length === 0 && declNames.length === 0) {
            return '#';
        } else if (declNames.length === 0) {
            return '#' + pkgNames.join('.');
        } else {
            return '#' + pkgNames.join('.') + ';' + declNames.join('.');
        }
    }

    function navLinkDeclIndex(decl_index) {
      return navLinkFqn(fullyQualifiedName(decl_index));
    }

    function resizeDomListDl(dlDom, desiredLen) {
        // add the missing dom entries
        var i, ev;
        for (i = dlDom.childElementCount / 2; i < desiredLen; i += 1) {
            dlDom.insertAdjacentHTML('beforeend', '<dt></dt><dd></dd>');
        }
        // remove extra dom entries
        while (desiredLen < dlDom.childElementCount / 2) {
            dlDom.removeChild(dlDom.lastChild);
            dlDom.removeChild(dlDom.lastChild);
        }
    }

    function resizeDomList(listDom, desiredLen, templateHtml) {
        // add the missing dom entries
        var i, ev;
        for (i = listDom.childElementCount; i < desiredLen; i += 1) {
            listDom.insertAdjacentHTML('beforeend', templateHtml);
        }
        // remove extra dom entries
        while (desiredLen < listDom.childElementCount) {
            listDom.removeChild(listDom.lastChild);
        }
    }

    function typeIndexName(typeIndex, wantHtml, wantLink, fnDecl, skipFnName) {
        var typeObj = zigAnalysis.types[typeIndex];
        if (wantLink) {
            var declIndex = getCanonTypeDecl(typeIndex);
            var declPath = getCanonDeclPath(declIndex);
            var haveLink = declPath != null;
            var typeNameHtml = typeName(typeObj, true, !haveLink, fnDecl, skipFnName);
            if (haveLink) {
                return '<a href="' + navLink(declPath.pkgNames, declPath.declNames) + '">' + typeNameHtml + '</a>';
            } else {
                return typeNameHtml;
            }
        } else {
            return typeName(typeObj, wantHtml, false, fnDecl, skipFnName);
        }
    }

    function typeName(typeObj, wantHtml, wantSubLink, fnDecl, skipFnName) {
        switch (typeObj.kind) {
            case typeKinds.Array:
                var name = "[";
                if (wantHtml) {
                    name += '<span class="tok-number">' + typeObj.len + '</span>';
                } else {
                    name += typeObj.len;
                }
                name += "]";
                name += typeIndexName(typeObj.elem, wantHtml, wantSubLink, null);
                return name;
            case typeKinds.Pointer:
                var name = "";
                switch (typeObj.len) {
                    case 0:
                    default:
                        name += "*";
                        break;
                    case 1:
                        name += "[*]";
                        break;
                    case 2:
                        name += "[]";
                        break;
                    case 3:
                        name += "[*c]";
                        break;
                }
                if (typeObj['const']) {
                    if (wantHtml) {
                        name += '<span class="tok-kw">const</span> ';
                    } else {
                        name += "const ";
                    }
                }
                if (typeObj['volatile']) {
                    if (wantHtml) {
                        name += '<span class="tok-kw">volatile</span> ';
                    } else {
                        name += "volatile ";
                    }
                }
                if (typeObj.align != null) {
                    if (wantHtml) {
                        name += '<span class="tok-kw">align</span>(';
                    } else {
                        name += "align(";
                    }
                    if (wantHtml) {
                        name += '<span class="tok-number">' + typeObj.align + '</span>';
                    } else {
                        name += typeObj.align;
                    }
                    if (typeObj.hostIntBytes != null) {
                        name += ":";
                        if (wantHtml) {
                            name += '<span class="tok-number">' + typeObj.bitOffsetInHost + '</span>';
                        } else {
                            name += typeObj.bitOffsetInHost;
                        }
                        name += ":";
                        if (wantHtml) {
                            name += '<span class="tok-number">' + typeObj.hostIntBytes + '</span>';
                        } else {
                            name += typeObj.hostIntBytes;
                        }
                    }
                    name += ") ";
                }
                name += typeIndexName(typeObj.elem, wantHtml, wantSubLink, null);
                return name;
            case typeKinds.Float:
                if (wantHtml) {
                    return '<span class="tok-type">f' + typeObj.bits + '</span>';
                } else {
                    return "f" + typeObj.bits;
                }
            case typeKinds.Int:
                var signed = (typeObj.i != null) ? 'i' : 'u';
                var bits = typeObj[signed];
                if (wantHtml) {
                    return '<span class="tok-type">' + signed + bits + '</span>';
                } else {
                    return signed + bits;
                }
            case typeKinds.ComptimeInt:
                if (wantHtml) {
                    return '<span class="tok-type">comptime_int</span>';
                } else {
                    return "comptime_int";
                }
            case typeKinds.ComptimeFloat:
                if (wantHtml) {
                    return '<span class="tok-type">comptime_float</span>';
                } else {
                    return "comptime_float";
                }
            case typeKinds.Type:
                if (wantHtml) {
                    return '<span class="tok-type">type</span>';
                } else {
                    return "type";
                }
            case typeKinds.Bool:
                if (wantHtml) {
                    return '<span class="tok-type">bool</span>';
                } else {
                    return "bool";
                }
            case typeKinds.Void:
                if (wantHtml) {
                    return '<span class="tok-type">void</span>';
                } else {
                    return "void";
                }
            case typeKinds.NoReturn:
                if (wantHtml) {
                    return '<span class="tok-type">noreturn</span>';
                } else {
                    return "noreturn";
                }
            case typeKinds.ErrorSet:
                if (typeObj.errors == null) {
                    if (wantHtml) {
                        return '<span class="tok-type">anyerror</span>';
                    } else {
                        return "anyerror";
                    }
                } else {
                    if (wantHtml) {
                        return escapeHtml(typeObj.name);
                    } else {
                        return typeObj.name;
                    }
                }
            case typeKinds.ErrorUnion:
                var errSetTypeObj = zigAnalysis.types[typeObj.err];
                var payloadHtml = typeIndexName(typeObj.payload, wantHtml, wantSubLink, null);
                if (fnDecl != null && errSetTypeObj.fn === fnDecl.value) {
                    // function index parameter supplied and this is the inferred error set of it
                    return "!" + payloadHtml;
                } else {
                    return typeIndexName(typeObj.err, wantHtml, wantSubLink, null) + "!" + payloadHtml;
                }
            case typeKinds.Fn:
                var payloadHtml = "";
                if (wantHtml) {
                    payloadHtml += '<span class="tok-kw">fn</span>';
                    if (fnDecl != null && !skipFnName) {
                        payloadHtml += ' <span class="tok-fn">' + escapeHtml(fnDecl.name) + '</span>';
                    }
                } else {
                    payloadHtml += 'fn'
                }
                payloadHtml += '(';
                if (typeObj.args != null) {
                    for (let i = 0; i < typeObj.args.length; i += 1) {
                        if (i != 0) {
                            payloadHtml += ', ';
                        }
                        var argTypeIndex = typeObj.args[i];
                        if (argTypeIndex != null) {
                            payloadHtml += typeIndexName(argTypeIndex, wantHtml, wantSubLink);
                        } else if (wantHtml) {
                            payloadHtml += '<span class="tok-kw">var</span>';
                        } else {
                            payloadHtml += 'var';
                        }
                    }
                }

                payloadHtml += ') ';
                if (typeObj.ret != null) {
                    payloadHtml += typeIndexName(typeObj.ret, wantHtml, wantSubLink, fnDecl);
                } else if (wantHtml) {
                    payloadHtml += '<span class="tok-kw">var</span>';
                } else {
                    payloadHtml += 'var';
                }
                return payloadHtml;
            default:
                if (wantHtml) {
                    return escapeHtml(typeObj.name);
                } else {
                    return typeObj.name;
                }
        }
    }

    function renderErrorSet(errSetType) {
        if (errSetType.errors == null) {
            domFnErrorsAnyError.classList.remove("hidden");
        } else {
            var errorList = [];
            for (let i = 0; i < errSetType.errors.length; i += 1) {
                var errObj = zigAnalysis.errors[errSetType.errors[i]];
                var srcObj = zigAnalysis.astNodes[errObj.src];
                errorList.push({
                    err: errObj,
                    docs: srcObj.docs,
                });
            }
            errorList.sort(function(a, b) {
                return operatorCompare(a.err.name.toLowerCase(), b.err.name.toLowerCase());
            });

            resizeDomListDl(domListFnErrors, errorList.length);
            for (let i = 0; i < errorList.length; i += 1) {
                var nameTdDom = domListFnErrors.children[i * 2 + 0];
                var descTdDom = domListFnErrors.children[i * 2 + 1];
                nameTdDom.textContent = errorList[i].err.name;
                var docs = errorList[i].docs;
                if (docs != null) {
                    descTdDom.innerHTML = markdown(docs);
                } else {
                    descTdDom.textContent = "";
                }
            }
            domTableFnErrors.classList.remove("hidden");
        }
        domSectFnErrors.classList.remove("hidden");
    }

    function renderValue(decl) {
        domFnProtoCode.innerHTML = '<span class="tok-kw">pub</span> <span class="tok-kw">const</span> ' +
            escapeHtml(decl.name) + ': ' + typeIndexName(decl.type, true, true);

        var docs = zigAnalysis.astNodes[decl.src].docs;
        if (docs != null) {
            domFnDocs.innerHTML = markdown(docs);
            domFnDocs.classList.remove("hidden");
        }

        domFnProto.classList.remove("hidden");
    }

    function renderVar(decl) {
        domFnProtoCode.innerHTML = '<span class="tok-kw">pub</span> <span class="tok-kw">var</span> ' +
            escapeHtml(decl.name) + ': ' + typeIndexName(decl.type, true, true);

        var docs = zigAnalysis.astNodes[decl.src].docs;
        if (docs != null) {
            domFnDocs.innerHTML = markdown(docs);
            domFnDocs.classList.remove("hidden");
        }

        domFnProto.classList.remove("hidden");
    }

    function renderNamespace(decl_index) {
        renderNav();

        const typesList = [];
        const namespacesList = [];
        const errSetsList = [];
        const fnsList = [];
        const varsList = [];
        const valsList = [];
        const members = namespaceMembers(decl_index, false);

        member_loop: for (let i = 0; i < members.length; i += 1) {
          let member = members[i];
          while (true) {
            const member_category = wasm_exports.categorize_decl(member);
            switch (member_category) {
              case CAT_namespace:
                namespacesList.push(member);
                continue member_loop;
              case CAT_global_variable:
                varsList.push(member);
                continue member_loop;
              case CAT_function:
                fnsList.push(member);
                continue member_loop;
              case CAT_type:
                typesList.push(member);
                continue member_loop;
              case CAT_error_set:
                errSetsList.push(member);
                continue member_loop;
              case CAT_global_const:
              case CAT_primitive_true:
              case CAT_primitive_false:
              case CAT_primitive_null:
                valsList.push(member);
                continue member_loop;
              case CAT_alias:
                // TODO: handle aliasing loop
                member = wasm_exports.get_aliasee();
                continue;
              default:
                throw new Error("uknown category: " + member_category);
            }
          }
        }

        typesList.sort(byDeclIndexName);
        namespacesList.sort(byDeclIndexName);
        errSetsList.sort(byDeclIndexName);
        fnsList.sort(byDeclIndexName);
        varsList.sort(byDeclIndexName);
        valsList.sort(byDeclIndexName);

        if (typesList.length !== 0) {
            resizeDomList(domListTypes, typesList.length, '<li><a href="#"></a></li>');
            for (let i = 0; i < typesList.length; i += 1) {
                const liDom = domListTypes.children[i];
                const aDom = liDom.children[0];
                const decl = typesList[i];
                aDom.textContent = declIndexName(decl);
                aDom.setAttribute('href', navLinkDeclIndex(decl));
            }
            domSectTypes.classList.remove("hidden");
        }
        if (namespacesList.length !== 0) {
            resizeDomList(domListNamespaces, namespacesList.length, '<li><a href="#"></a></li>');
            for (let i = 0; i < namespacesList.length; i += 1) {
                const liDom = domListNamespaces.children[i];
                const aDom = liDom.children[0];
                const decl = namespacesList[i];
                aDom.textContent = declIndexName(decl);
                aDom.setAttribute('href', navLinkDeclIndex(decl));
            }
            domSectNamespaces.classList.remove("hidden");
        }

        if (errSetsList.length !== 0) {
            resizeDomList(domListErrSets, errSetsList.length, '<li><a href="#"></a></li>');
            for (let i = 0; i < errSetsList.length; i += 1) {
                const liDom = domListErrSets.children[i];
                const aDom = liDom.children[0];
                const decl = errSetsList[i];
                aDom.textContent = declIndexName(decl);
                aDom.setAttribute('href', navLinkDeclIndex(decl));
            }
            domSectErrSets.classList.remove("hidden");
        }

        if (fnsList.length !== 0) {
            resizeDomList(domListFns, fnsList.length,
                '<tr><td><a href="#"></a></td><td></td><td></td></tr>');
            for (let i = 0; i < fnsList.length; i += 1) {
                const decl = fnsList[i];
                const trDom = domListFns.children[i];

                const tdName = trDom.children[0];
                const tdNameA = tdName.children[0];
                const tdType = trDom.children[1];
                const tdDesc = trDom.children[2];

                tdNameA.setAttribute('href', navLinkDeclIndex(decl));
                tdNameA.textContent = declIndexName(decl);

                tdType.innerHTML = declTypeHtml(decl);
                tdDesc.innerHTML = declDocsHtmlShort(decl);
            }
            domSectFns.classList.remove("hidden");
        }

        const fields = getFields(decl_index);
        if (fields.length !== 0) {
            resizeDomList(domListFields, fields.length, '<div></div>');
            for (let i = 0; i < fields.length; i += 1) {
                const field = fields[i];
                const divDom = domListFields.children[i];
                divDom.innerHTML = fieldHtml(field);
            }
            domSectFields.classList.remove("hidden");
        }

        if (varsList.length !== 0) {
            resizeDomList(domListGlobalVars, varsList.length,
                '<tr><td><a href="#"></a></td><td></td><td></td></tr>');
            for (let i = 0; i < varsList.length; i += 1) {
                const decl = varsList[i];
                const trDom = domListGlobalVars.children[i];

                const tdName = trDom.children[0];
                const tdNameA = tdName.children[0];
                const tdType = trDom.children[1];
                const tdDesc = trDom.children[2];

                tdNameA.setAttribute('href', navLinkDeclIndex(decl));
                tdNameA.textContent = declIndexName(decl);

                tdType.innerHTML = declTypeHtml(decl);
                tdDesc.innerHTML = declDocsHtmlShort(decl);
            }
            domSectGlobalVars.classList.remove("hidden");
        }

        if (valsList.length !== 0) {
            resizeDomList(domListValues, valsList.length,
                '<tr><td><a href="#"></a></td><td></td><td></td></tr>');
            for (let i = 0; i < valsList.length; i += 1) {
                const decl = valsList[i];
                const trDom = domListValues.children[i];

                const tdName = trDom.children[0];
                const tdNameA = tdName.children[0];
                const tdType = trDom.children[1];
                const tdDesc = trDom.children[2];

                tdNameA.setAttribute('href', navLinkDeclIndex(decl));
                tdNameA.textContent = declIndexName(decl);

                tdType.innerHTML = declTypeHtml(decl);
                tdDesc.innerHTML = declDocsHtmlShort(decl);
            }
            domSectValues.classList.remove("hidden");
        }
    }

    function operatorCompare(a, b) {
        if (a === b) {
            return 0;
        } else if (a < b) {
            return -1;
        } else {
            return 1;
        }
    }

    function indexTypeKinds() {
        var map = {};
        for (let i = 0; i < zigAnalysis.typeKinds.length; i += 1) {
            map[zigAnalysis.typeKinds[i]] = i;
        }
        // This is just for debugging purposes, not needed to function
        var assertList = ["Type","Void","Bool","NoReturn","Int","Float","Pointer","Array","Struct",
            "ComptimeFloat","ComptimeInt","Undefined","Null","Optional","ErrorUnion","ErrorSet","Enum",
            "Union","Fn","BoundFn","ArgTuple","Opaque","Frame","AnyFrame","Vector","EnumLiteral"];
        for (let i = 0; i < assertList.length; i += 1) {
            if (map[assertList[i]] == null) throw new Error("No type kind '" + assertList[i] + "' found");
        }
        return map;
    }

    function updateCurNav() {
        curNav.decl = null;
        curNav.tag = 0;
        curNavSearch = "";

        if (location.hash[0] === '#' && location.hash.length > 1) {
            const query = location.hash.substring(1);
            const qpos = query.indexOf("?");
            let nonSearchPart;
            if (qpos === -1) {
                nonSearchPart = query;
            } else {
                nonSearchPart = query.substring(0, qpos);
                curNavSearch = decodeURIComponent(query.substring(qpos + 1));
            }

            if (nonSearchPart.length > 0) {
              curNav.tag = 1;
              curNav.decl = findDecl(nonSearchPart);
            }
        }
    }

    function onHashChange() {
        updateCurNav();
        if (domSearch.value !== curNavSearch) {
            domSearch.value = curNavSearch;
        }
        render();
        if (imFeelingLucky) {
            imFeelingLucky = false;
            activateSelectedResult();
        }
    }

    function escapeHtml(text) {
        return text.replace(/[&"<>]/g, function (m) {
            return escapeHtmlReplacements[m];
        });
    }

    function shortDescMarkdown(docs) {
        var parts = docs.trim().split("\n");
        var firstLine = parts[0];
        return markdown(firstLine);
    }

    function markdown(mdText) {
      throw new Error("TODO delete this function");
    }

    function activateSelectedResult() {
        if (domSectSearchResults.classList.contains("hidden")) {
            return;
        }

        var liDom = domListSearchResults.children[curSearchIndex];
        if (liDom == null && domListSearchResults.children.length !== 0) {
            liDom = domListSearchResults.children[0];
        }
        if (liDom != null) {
            var aDom = liDom.children[0];
            location.href = aDom.getAttribute("href");
            curSearchIndex = -1;
        }
        domSearch.blur();
    }

    function onSearchKeyDown(ev) {
        switch (ev.which) {
            case 13:
                if (ev.shiftKey || ev.ctrlKey || ev.altKey) return;

                // detect if this search changes anything
                var terms1 = getSearchTerms();
                startSearch();
                updateCurNav();
                var terms2 = getSearchTerms();
                // we might have to wait for onHashChange to trigger
                imFeelingLucky = (terms1.join(' ') !== terms2.join(' '));
                if (!imFeelingLucky) activateSelectedResult();

                ev.preventDefault();
                ev.stopPropagation();
                return;
            case 27:
                if (ev.shiftKey || ev.ctrlKey || ev.altKey) return;

                domSearch.value = "";
                domSearch.blur();
                curSearchIndex = -1;
                ev.preventDefault();
                ev.stopPropagation();
                startSearch();
                return;
            case 38:
                if (ev.shiftKey || ev.ctrlKey || ev.altKey) return;

                moveSearchCursor(-1);
                ev.preventDefault();
                ev.stopPropagation();
                return;
            case 40:
                if (ev.shiftKey || ev.ctrlKey || ev.altKey) return;

                moveSearchCursor(1);
                ev.preventDefault();
                ev.stopPropagation();
                return;
            default:
                if (ev.shiftKey || ev.ctrlKey || ev.altKey) return;

                curSearchIndex = -1;
                ev.stopPropagation();
                startAsyncSearch();
                return;
        }
    }

    function moveSearchCursor(dir) {
        if (curSearchIndex < 0 || curSearchIndex >= domListSearchResults.children.length) {
            if (dir > 0) {
                curSearchIndex = -1 + dir;
            } else if (dir < 0) {
                curSearchIndex = domListSearchResults.children.length + dir;
            }
        } else {
            curSearchIndex += dir;
        }
        if (curSearchIndex < 0) {
            curSearchIndex = 0;
        }
        if (curSearchIndex >= domListSearchResults.children.length) {
            curSearchIndex = domListSearchResults.children.length - 1;
        }
        renderSearchCursor();
    }

    function onWindowKeyDown(ev) {
        switch (ev.which) {
            case 27:
                if (ev.shiftKey || ev.ctrlKey || ev.altKey) return;
                if (!domHelpModal.classList.contains("hidden")) {
                    domHelpModal.classList.add("hidden");
                    ev.preventDefault();
                    ev.stopPropagation();
                }
                break;
            case 83:
                if (ev.shiftKey || ev.ctrlKey || ev.altKey) return;
                domSearch.focus();
                domSearch.select();
                ev.preventDefault();
                ev.stopPropagation();
                startAsyncSearch();
                break;
            case 191:
                if (!ev.shiftKey || ev.ctrlKey || ev.altKey) return;
                ev.preventDefault();
                ev.stopPropagation();
                showHelpModal();
                break;
        }
    }

    function showHelpModal() {
        domHelpModal.classList.remove("hidden");
        domHelpModal.style.left = (window.innerWidth / 2 - domHelpModal.clientWidth / 2) + "px";
        domHelpModal.style.top = (window.innerHeight / 2 - domHelpModal.clientHeight / 2) + "px";
        domHelpModal.focus();
    }

    function clearAsyncSearch() {
        if (searchTimer != null) {
            clearTimeout(searchTimer);
            searchTimer = null;
        }
    }

    function startAsyncSearch() {
        clearAsyncSearch();
        searchTimer = setTimeout(startSearch, 100);
    }
    function startSearch() {
        clearAsyncSearch();
        var oldHash = location.hash;
        var parts = oldHash.split("?");
        var newPart2 = (domSearch.value === "") ? "" : ("?" + domSearch.value);
        location.hash = (parts.length === 1) ? (oldHash + newPart2) : (parts[0] + newPart2);
    }
    function getSearchTerms() {
        var list = curNavSearch.trim().split(/[ \r\n\t]+/);
        list.sort();
        return list;
    }
    function renderSearch() {
        renderNav();

        const ignoreCase = (curNavSearch.toLowerCase() === curNavSearch);
        const results = executeQuery(curNavSearch, ignoreCase);

        if (results.length !== 0) {
            resizeDomList(domListSearchResults, results.length, '<li><a href="#"></a></li>');

            for (let i = 0; i < results.length; i += 1) {
                const liDom = domListSearchResults.children[i];
                const aDom = liDom.children[0];
                const match = results[i];
                const full_name = fullyQualifiedName(match);
                aDom.textContent = full_name;
                aDom.setAttribute('href', navLinkFqn(full_name));
            }
            renderSearchCursor();

            domSectSearchResults.classList.remove("hidden");
        } else {
            domSectSearchNoResults.classList.remove("hidden");
        }
    }

    function renderSearchCursor() {
        for (let i = 0; i < domListSearchResults.children.length; i += 1) {
            var liDom = domListSearchResults.children[i];
            if (curSearchIndex === i) {
                liDom.classList.add("selected");
            } else {
                liDom.classList.remove("selected");
            }
        }
    }

    function updatePackageList() {
      packageList.length = 0;
      for (let i = 0;; i += 1) {
        const name = unwrapString(wasm_exports.package_name(i));
        if (name.length == 0) break;
        packageList.push(name);
      }
    }

    function byDeclIndexName(a, b) {
      const a_name = declIndexName(a);
      const b_name = declIndexName(b);
      return operatorCompare(a_name, b_name);
    }

    function decodeString(ptr, len) {
      if (len === 0) return "";
      return text_decoder.decode(new Uint8Array(wasm_exports.memory.buffer, ptr, len));
    }

    function unwrapString(bigint) {
      const ptr = Number(bigint & 0xffffffffn);
      const len = Number(bigint >> 32n);
      return decodeString(ptr, len);
    }

    function declTypeHtml(decl_index) {
      return unwrapString(wasm_exports.decl_type_html(decl_index));
    }

    function declDocsHtmlShort(decl_index) {
      return unwrapString(wasm_exports.decl_docs_html(decl_index, true));
    }

    function fullyQualifiedName(decl_index) {
      return unwrapString(wasm_exports.decl_fqn(decl_index));
    }

    function declIndexName(decl_index) {
      return unwrapString(wasm_exports.decl_name(decl_index));
    }

    function setQueryString(s) {
      const jsArray = text_encoder.encode(s);
      const len = jsArray.length;
      const ptr = wasm_exports.query_begin(len);
      const wasmArray = new Uint8Array(wasm_exports.memory.buffer, ptr, len);
      wasmArray.set(jsArray);
    }

    function executeQuery(query_string, ignore_case) {
      setQueryString(query_string);
      const ptr = wasm_exports.query_exec(ignore_case);
      const head = new Uint32Array(wasm_exports.memory.buffer, ptr, 1);
      const len = head[0];
      return new Uint32Array(wasm_exports.memory.buffer, ptr + 4, len);
    }

    function namespaceMembers(decl_index, include_private) {
      const bigint = wasm_exports.namespace_members(decl_index, include_private);
      const ptr = Number(bigint & 0xffffffffn);
      const len = Number(bigint >> 32n);
      return new Uint32Array(wasm_exports.memory.buffer, ptr, len);
    }

    function getFields(decl_index) {
      // TODO
      return [];
    }

    function findDecl(fqn) {
      setInputString(fqn);
      const result = wasm_exports.find_decl();
      if (result === -1) return null;
      return result;
    }

    function declParent(decl_index) {
      const result = wasm_exports.decl_parent(decl_index);
      if (result === -1) return null;
      return result;
    }

    function setInputString(s) {
      const jsArray = text_encoder.encode(s);
      const len = jsArray.length;
      const ptr = wasm_exports.set_input_string(len);
      const wasmArray = new Uint8Array(wasm_exports.memory.buffer, ptr, len);
      wasmArray.set(jsArray);
    }
})();

