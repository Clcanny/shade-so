// Copyright (c) @ 2021 junbin.rjb.
// All right reserved.
//
// Author: junbin.rjb <837940593@qq.com>
// Created: 2021/02/07
// Description

#ifndef SRC_CONST_H_
#define SRC_CONST_H_

namespace shade_so {
namespace sec_names {

extern const char* kPlt;
extern const char* kGotPlt;
extern const char* kRelPlt;
extern const char* kRelaPlt;
extern const char* kInit;
extern const char* kInitArray;
extern const char* kFini;
extern const char* kFiniArray;
extern const char* kData;
extern const char* kBss;
extern const char* kRodata;
extern const char* kSymtab;
extern const char* kRelaDyn;
extern const char* kStrtab;
extern const char* kPltGot;
extern const char* kGot;
extern const char* kText;
extern const char* kDynsym;
extern const char* kDynstr;
extern const char* kTbss;
extern const char* kTdata;

}  // namespace sec_names

namespace func_names {

extern const char* kLibcCsuInit;

}  // namespace func_names
}  // namespace shade_so

#endif  // SRC_CONST_H_
