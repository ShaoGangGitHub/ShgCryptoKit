//
//  ShgSM3OC.m
//  ShgCryptoKit
//
//  Created by shg on 2020/12/1.
//

#import "ShgSM3OC.h"

typedef unsigned char ShgUnsignedChar;

typedef unsigned long ShgUnsignedLong;

typedef const char ShgConstChar;

typedef int ShgInt;

typedef uint32_t ShgUInt32;

#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
(n) = ( (ShgUInt32) (b)[(i)    ] << 24 )        \
| ( (ShgUInt32) (b)[(i) + 1] << 16 )        \
| ( (ShgUInt32) (b)[(i) + 2] <<  8 )        \
| ( (ShgUInt32) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
(b)[(i)    ] = (ShgUnsignedChar) ( (n) >> 24 );       \
(b)[(i) + 1] = (ShgUnsignedChar) ( (n) >> 16 );       \
(b)[(i) + 2] = (ShgUnsignedChar) ( (n) >>  8 );       \
(b)[(i) + 3] = (ShgUnsignedChar) ( (n)       );       \
}
#endif

typedef struct {
    
    ShgUnsignedLong total[2];
    
    ShgUnsignedLong state[8];
    
    ShgUnsignedChar buffer[64];
    
    ShgUnsignedChar inpading[64];
    
    ShgUnsignedChar outpading[64];
    
}ShgSm3Context;

static const ShgUnsignedChar ShgSm3Padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

@implementation ShgSM3OC


+ (void)sm3Encryto:(NSData *)data finish:(void (^)(NSData *, NSString *, NSString *))callBack
{
    if (data == nil) {
        callBack(nil,nil,nil);
        return;
    }
    
    if (data.length == 0) {
        callBack(nil,nil,nil);
        return;
    }
    
    ShgInt inputLenght = (ShgInt)data.length;
    
    ShgUnsignedChar inputChar[inputLenght];
    
    memcpy(inputChar, data.bytes, inputLenght);
    
    ShgInt outLenght = 32;
    
    ShgUnsignedChar output[outLenght];
    
    ShgSm3Context ctx;
    
    [self shgSm3Starts:&ctx];
    
    [self shgSm3Update:&ctx input:inputChar inLength:inputLenght];
    
    [self shgSm3Finish:&ctx output:output];
    
    memset(&ctx, 0, sizeof(ShgSm3Context));
    
    NSData *outData = [[NSData alloc] initWithBytes:output length:outLenght];
    
    NSMutableString *hexstr = @"".mutableCopy;
    
    for (ShgInt i = 0; i < outLenght; i++) {
        [hexstr appendFormat:@"%02x",output[i]];
    }
    
    NSString *base64 = [outData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
    callBack(outData,base64,hexstr.mutableCopy);
}

+ (void)shgSm3Starts:(ShgSm3Context *)ctx
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;
    ctx->state[0] = 0x7380166F;
    ctx->state[1] = 0x4914B2B9;
    ctx->state[2] = 0x172442D7;
    ctx->state[3] = 0xDA8A0600;
    ctx->state[4] = 0xA96F30BC;
    ctx->state[5] = 0x163138AA;
    ctx->state[6] = 0xE38DEE4D;
    ctx->state[7] = 0xB0FB0E4E;
}

+ (void)shgSm3Update:(ShgSm3Context *)ctx input:(ShgUnsignedChar *)input inLength:(ShgInt)ilen
{
    ShgInt fill;
    
    ShgUInt32  left;
    
    if (ilen <= 0) {
        return;
    }
    
    left = ctx->total[0] & 0x3F;
    
    fill = 64 - left;
    
    ctx->total[0] += ilen;
    
    ctx->total[0] &= 0xFFFFFFFF;
    
    if (ctx->total[0] < (ShgUInt32)ilen) {
        ctx->total[1]++;
    }
    
    if (left && ilen >= fill) {
        memcpy((void *)(ctx->buffer + left),(void *)input, fill);
        
        [self shgSm3Process:ctx data:ctx->buffer];
        
        input += fill;
        
        ilen  -= fill;
        
        left = 0;
    }
    
    while(ilen >= 64)
    {
        [self shgSm3Process:ctx data:input];
        
        input += 64;
        
        ilen  -= 64;
    }
    
    if (ilen > 0) {
        memcpy((void *)(ctx->buffer + left),(void *)input, ilen);
    }
}

+ (void)shgSm3Finish:(ShgSm3Context *)ctx output:(ShgUnsignedChar[32])output
{
    ShgUInt32  last, padn;
    
    ShgUInt32  high, low;
    
    ShgUnsignedChar msglen[8];
    
    high = (ShgUInt32)((ctx->total[0] >> 29) | (ctx->total[1] <<  3));
    
    low  = (ShgUInt32)(ctx->total[0] << 3);
    
    PUT_ULONG_BE( high, msglen, 0 );
    PUT_ULONG_BE( low,  msglen, 4 );
    
    last = ctx->total[0] & 0x3F;
    
    padn = (last < 56) ? (56 - last) : (120 - last);
    
    [self shgSm3Update:ctx input:(ShgUnsignedChar *)ShgSm3Padding inLength:padn];
    
    [self shgSm3Update:ctx input:msglen inLength:8];
    
    PUT_ULONG_BE( ctx->state[0], output,  0 );
    PUT_ULONG_BE( ctx->state[1], output,  4 );
    PUT_ULONG_BE( ctx->state[2], output,  8 );
    PUT_ULONG_BE( ctx->state[3], output, 12 );
    PUT_ULONG_BE( ctx->state[4], output, 16 );
    PUT_ULONG_BE( ctx->state[5], output, 20 );
    PUT_ULONG_BE( ctx->state[6], output, 24 );
    PUT_ULONG_BE( ctx->state[7], output, 28 );
}

+ (void)shgSm3Process:(ShgSm3Context *)ctx data:(ShgUnsignedChar[64])data
{
    ShgUInt32  SS1, SS2, TT1, TT2, W[68],W1[64];
    
    ShgUInt32  A, B, C, D, E, F, G, H;
    
    ShgUInt32  T[64];
    
    ShgUInt32  Temp1,Temp2,Temp3,Temp4,Temp5;
    
    for(ShgInt j = 0; j < 16; j++) {
        T[j] = 0x79CC4519;
    }
    for(ShgInt j =16; j < 64; j++) {
        T[j] = 0x7A879D8A;
    }
    
    GET_ULONG_BE( W[ 0], data, 0 );
    GET_ULONG_BE( W[ 1], data,  4 );
    GET_ULONG_BE( W[ 2], data,  8 );
    GET_ULONG_BE( W[ 3], data, 12 );
    GET_ULONG_BE( W[ 4], data, 16 );
    GET_ULONG_BE( W[ 5], data, 20 );
    GET_ULONG_BE( W[ 6], data, 24 );
    GET_ULONG_BE( W[ 7], data, 28 );
    GET_ULONG_BE( W[ 8], data, 32 );
    GET_ULONG_BE( W[ 9], data, 36 );
    GET_ULONG_BE( W[10], data, 40 );
    GET_ULONG_BE( W[11], data, 44 );
    GET_ULONG_BE( W[12], data, 48 );
    GET_ULONG_BE( W[13], data, 52 );
    GET_ULONG_BE( W[14], data, 56 );
    GET_ULONG_BE( W[15], data, 60 );
    
#define FF0(x,y,z) ( (x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))
    
#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )
    
    
#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))
    
#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17))
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23))
    
    for(ShgInt j = 16; j < 68; j++) {
        
        Temp1 = W[j-16] ^ W[j-9];
        Temp2 = ROTL(W[j-3],15);
        Temp3 = Temp1 ^ Temp2;
        Temp4 = P1(Temp3);
        Temp5 =  ROTL(W[j - 13],7 ) ^ W[j-6];
        W[j] = Temp4 ^ Temp5;
    }
    
    for(ShgInt j =  0; j < 64; j++) {
        W1[j] = W[j] ^ W[j+4];
    }
    
    A = (ShgUInt32)ctx->state[0];
    B = (ShgUInt32)ctx->state[1];
    C = (ShgUInt32)ctx->state[2];
    D = (ShgUInt32)ctx->state[3];
    E = (ShgUInt32)ctx->state[4];
    F = (ShgUInt32)ctx->state[5];
    G = (ShgUInt32)ctx->state[6];
    H = (ShgUInt32)ctx->state[7];
    
    for(ShgInt j =0; j < 16; j++) {
        
        SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7);
        SS2 = SS1 ^ ROTL(A,12);
        TT1 = FF0(A,B,C) + D + SS2 + W1[j];
        TT2 = GG0(E,F,G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B,9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F,19);
        F = E;
        E = P0(TT2);
    }
    
    for(ShgInt j =16; j < 64; j++) {
        
        SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7);
        SS2 = SS1 ^ ROTL(A,12);
        TT1 = FF1(A,B,C) + D + SS2 + W1[j];
        TT2 = GG1(E,F,G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B,9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F,19);
        F = E;
        E = P0(TT2);
    }
    
    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

@end
