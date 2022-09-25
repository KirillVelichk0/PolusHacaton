#include "auth.hpp"
#include <openssl/rand.h>
using namespace std::string_literals;
namespace Polus{
AuthTempl::AuthTempl(const TableBasicData& data) : dataBaseTempl(data){
    //заменить на макросы
    this->session = std::make_unique<mysqlx::Session>(33060, "root", "12345434");

}
bool AuthTempl::IsInclude(const RegData& data,  mysqlx::Table& table) const{
    auto row = table.select(L"email"s).where(L"email like :email"s).bind(L"email"s, std::get<0>(data)).execute();
    return row.count() != 0;
}
//стоит дописать проверку вводимых пользователем данных
RegistState AuthTempl::TryToRegistr(const RegData& data) const{
    RegistState result = RegistState::Ok;
    try{
        auto schema = this->session->getSchema(this->dataBaseTempl.dbName);
        auto table = schema.getTable(this->dataBaseTempl.tableName);
        if(this->IsInclude(data, table)){
            result = RegistState::AlreadyRegistered;
        }
        //refactor this shit!!!
        //во-первых, надо захешировать данные с солью.
        //во-вторых, надо преобразовать соль в utf-формат и сохранить в бд
        else{
            const std::size_t bCount = sizeof(wchar_t) * 15;
            unsigned char buf[bCount];
            auto written = RAND_bytes(buf, bCount);
            if(written == 1){
                std::wstring salt;
                for(auto cur = buf; cur < buf + bCount; cur = cur + sizeof(wchar_t)){
                    wchar_t saltSymb;
                    std::memcpy(&saltSymb, cur, sizeof(wchar_t));
                    salt.push_back(saltSymb);
                }
                std::size_t NonSoltedSz = std::get<2>(data).length() * sizeof(wchar_t);
                std::size_t salted1Size = NonSoltedSz + bCount;
                unsigned char saltedBuf1[salted1Size];
                std::memcpy(saltedBuf1, std::get<2>(data).c_str(), NonSoltedSz);
                std::memcpy(saltedBuf1 + NonSoltedSz, buf, bCount);
                unsigned char hash1[SHA256_DIGEST_LENGTH];
                unsigned char hash2[SHA256_DIGEST_LENGTH];
                SHA256_CTX ctx1;
                SHA256_Init(&ctx1);
                SHA256_Update(&ctx1, saltedBuf1, salted1Size);
                SHA256_Final(hash1, &ctx1);
                SHA256_CTX ctx2;
                //прототип глобальной соли, потом сделать через макрос с конфигов!!!
                auto globalSalt = L"qwert"s;
                std::size_t saltGlSize = globalSalt.length() * sizeof(wchar_t);
                std::size_t salted2Size = SHA256_DIGEST_LENGTH + saltGlSize;
                unsigned char salted2Buf[salted2Size];
                std::memcpy(salted2Buf, hash1, SHA256_DIGEST_LENGTH);
                std::memcpy(salted2Buf + SHA256_DIGEST_LENGTH, globalSalt.c_str(), saltGlSize);
                SHA256_Init(&ctx2);
                SHA256_Update(&ctx2, salted2Buf, salted2Size);
                SHA256_Final(hash2, &ctx2);

            }

        }
    } catch(mysqlx::Error& e){
        result = RegistState::UncorrectLoginOrPassword;
    }
    return result;
}
}
