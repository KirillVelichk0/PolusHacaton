#include "auth.hpp"
#include <openssl/rand.h>
#include <cwctype>
#include <string>
#include <optional>
#include <locale>
#include <ctype.h>
#include <uchar.h>
using namespace std::string_literals;
namespace Polus{
AuthTempl::AuthTempl(const TableBasicData& data) : dataBaseTempl(data){
    //заменить на макросы
    this->session = std::make_unique<mysqlx::Session>(33060, "root", "12345434");

}
bool AuthTempl::IsInclude(const RegData& data,  mysqlx::Table& table) const{
    auto row = table.select("email").where("email like :email").bind("email", std::get<0>(data).c_str()).execute();
    return row.count() != 0;
}
bool CheckUsername(std::u16string_view view){
    if(view.size() < 5 || view.size() > 19){
        return false;
    }
    auto& facet = std::use_facet<std::ctype<char16_t>>(std::locale());
    auto IsSymbOkPred = [&facet](char16_t symb){
        symb = facet.tolower(symb);
        return bool(symb >= u'a' && symb <= u'z')|| bool(symb >= u'а' && symb <= u'я') || bool(symb == u'ё') ||
                bool(symb >= u'0' && symb <= u'9') || bool(symb == u'_');

    };
    bool result = true;

    for(auto cur = view.cbegin(); cur != view.cend(); cur = std::next(cur, 1)){
        if(!IsSymbOkPred(*cur)){
            result = false;
            break;
        }
    }
    return result;
}
bool CheckPassword(std::u16string_view view){
    if(view.size() < 8 || view.size() > 30){
        return false;
    }
    bool result = true;
    auto& facet = std::use_facet<std::ctype<char16_t>>(std::locale());

    for(auto cur = view.cbegin(); cur != view.cend(); cur = std::next(cur,1)){
        if(facet.is(facet.space, *cur)){
            result = false;
            break;
        }
    }
    return result;
}
bool CheckEmail(std::u16string_view view){
    bool result = true;
    if(view.length() > 129 || view.length() < 3){
        result = false;
    }
    else{
        auto IsOkSymb = [isDogHere = false](auto symb) mutable{
            if(symb == u'@'){
                if(!isDogHere){
                    isDogHere = true;
                    return true;
                }
                else{
                    return false;
                }
            }
            return (symb >= u'a' && symb <= u'z')  || symb == u'-' || symb == u'+' || symb == u'\'' ||
                    (symb >= u'0' && symb <= u'9') || symb == u'_' || symb == u'.';

        };
        for(auto cur = view.cbegin(); cur != view.cend(); cur = std::next(cur, 1)){
            if(!IsOkSymb(*cur)){
                result = false;
                break;
            }
        }
    }

    return result;
}
bool CheckRegData(const RegData& data){
    return CheckEmail(std::get<0>(data)) && CheckUsername(std::get<1>(data)) && CheckPassword(std::get<2>(data));
}
//стоит дописать проверку вводимых пользователем данных
RegistState AuthTempl::TryToRegistr(const RegData& data, std::string_view globalSalt) const{
    RegistState result = RegistState::Ok;
    if(!CheckRegData(data)){
        result = RegistState::UncorrectLoginOrPassword;
    }
    else{
        try{
            auto schema = this->session->getSchema(this->dataBaseTempl.dbName);
            auto table = schema.getTable(this->dataBaseTempl.tableName);
            if(this->IsInclude(data, table)){
                result = RegistState::AlreadyRegistered;
            }
            else{
                const std::size_t bCount = 30;
                unsigned char salt[bCount];
                auto written = RAND_bytes(salt, bCount);
                if(written == 1){
                    std::size_t NonSoltedSz = std::get<2>(data).length() * sizeof(char16_t);
                    const std::size_t salted1Size = NonSoltedSz + bCount;
                    std::unique_ptr<unsigned char[]> saltedBuf1 = std::make_unique<unsigned char[]>(salted1Size);
                    std::memcpy(saltedBuf1.get(), std::get<2>(data).c_str(), NonSoltedSz);
                    std::memcpy(saltedBuf1.get() + NonSoltedSz, salt, bCount);
                    unsigned char hash1[SHA256_DIGEST_LENGTH];
                    unsigned char hash2[SHA256_DIGEST_LENGTH];
                    SHA256_CTX ctx1;
                    SHA256_Init(&ctx1);
                    SHA256_Update(&ctx1, saltedBuf1.get(), salted1Size);
                    SHA256_Final(hash1, &ctx1);
                    SHA256_CTX ctx2;
                    std::size_t saltGlSize = globalSalt.length();
                    const size_t salted2Size = SHA256_DIGEST_LENGTH + saltGlSize;
                    std::unique_ptr<unsigned char[]> saltedBuf2 = std::make_unique<unsigned char[]>(salted2Size);
                    std::memcpy(saltedBuf2.get(), hash1, SHA256_DIGEST_LENGTH);
                    std::memcpy(saltedBuf2.get() + SHA256_DIGEST_LENGTH, globalSalt.data(), saltGlSize);
                    SHA256_Init(&ctx2);
                    SHA256_Update(&ctx2, saltedBuf2.get(), salted2Size);
                    SHA256_Final(hash2, &ctx2);
                    table.insert("id", "email", "username", "passH", "salt").values("NULL",
                                 L"a", L"d", (char*)(hash2), (char*)salt);
                }
                else{
                    throw std::runtime_error("OpenSSL gen error");
                }
            }
        } catch(mysqlx::Error& e){
            result = RegistState::UncorrectLoginOrPassword;
        }
        catch(std::runtime_error& er){
            throw er;
        }
    }
    return result;
}
}
