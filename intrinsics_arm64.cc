/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "intrinsics_arm64.h"

#include "arch/arm64/instruction_set_features_arm64.h"
#include "art_method.h"
#include "code_generator_arm64.h"
#include "common_arm64.h"
#include "entrypoints/quick/quick_entrypoints.h"
#include "intrinsics.h"
#include "mirror/array-inl.h"
#include "mirror/string.h"
#include "thread.h"
#include "utils/arm64/assembler_arm64.h"
#include "utils/arm64/constants_arm64.h"

#include "vixl/a64/disasm-a64.h"
#include "vixl/a64/macro-assembler-a64.h"

using namespace vixl;   // NOLINT(build/namespaces)

namespace art {

namespace arm64 {

using helpers::DRegisterFrom;
using helpers::FPRegisterFrom;
using helpers::HeapOperand;
using helpers::LocationFrom;
using helpers::RegisterFrom;
using helpers::SRegisterFrom;
using helpers::WRegisterFrom;
using helpers::XRegisterFrom;


namespace {

ALWAYS_INLINE inline MemOperand AbsoluteHeapOperandFrom(Location location, size_t offset = 0) {
  return MemOperand(XRegisterFrom(location), offset);
}

}  // namespace

vixl::MacroAssembler* IntrinsicCodeGeneratorARM64::GetVIXLAssembler() {
  return codegen_->GetAssembler()->vixl_masm_;
}

ArenaAllocator* IntrinsicCodeGeneratorARM64::GetAllocator() {
  return codegen_->GetGraph()->GetArena();
}

#define __ codegen->GetAssembler()->vixl_masm_->

static void MoveFromReturnRegister(Location trg,
                                   Primitive::Type type,
                                   CodeGeneratorARM64* codegen) {
  if (!trg.IsValid()) {
    DCHECK(type == Primitive::kPrimVoid);
    return;
  }

  DCHECK_NE(type, Primitive::kPrimVoid);

  if (Primitive::IsIntegralType(type) || type == Primitive::kPrimNot) {
    Register trg_reg = RegisterFrom(trg, type);
    Register res_reg = RegisterFrom(ARM64ReturnLocation(type), type);
    __ Mov(trg_reg, res_reg, kDiscardForSameWReg);
  } else {
    FPRegister trg_reg = FPRegisterFrom(trg, type);
    FPRegister res_reg = FPRegisterFrom(ARM64ReturnLocation(type), type);
    __ Fmov(trg_reg, res_reg);
  }
}

static void MoveArguments(HInvoke* invoke, CodeGeneratorARM64* codegen) {
  InvokeDexCallingConventionVisitorARM64 calling_convention_visitor;
  IntrinsicVisitor::MoveArguments(invoke, codegen, &calling_convention_visitor);
}

// Slow-path for fallback (calling the managed code to handle the intrinsic) in an intrinsified
// call. This will copy the arguments into the positions for a regular call.
//
// Note: The actual parameters are required to be in the locations given by the invoke's location
//       summary. If an intrinsic modifies those locations before a slowpath call, they must be
//       restored!
class IntrinsicSlowPathARM64 : public SlowPathCodeARM64 {
 public:
  explicit IntrinsicSlowPathARM64(HInvoke* invoke) : invoke_(invoke) { }

  void EmitNativeCode(CodeGenerator* codegen_in) OVERRIDE {
    CodeGeneratorARM64* codegen = down_cast<CodeGeneratorARM64*>(codegen_in);
    __ Bind(GetEntryLabel());

    SaveLiveRegisters(codegen, invoke_->GetLocations());

    MoveArguments(invoke_, codegen);

    if (invoke_->IsInvokeStaticOrDirect()) {
      codegen->GenerateStaticOrDirectCall(invoke_->AsInvokeStaticOrDirect(), kArtMethodRegister);
      RecordPcInfo(codegen, invoke_, invoke_->GetDexPc());
    } else {
      UNIMPLEMENTED(FATAL) << "Non-direct intrinsic slow-path not yet implemented";
      UNREACHABLE();
    }

    // Copy the result back to the expected output.
    Location out = invoke_->GetLocations()->Out();
    if (out.IsValid()) {
      DCHECK(out.IsRegister());  // TODO: Replace this when we support output in memory.
      DCHECK(!invoke_->GetLocations()->GetLiveRegisters()->ContainsCoreRegister(out.reg()));
      MoveFromReturnRegister(out, invoke_->GetType(), codegen);
    }

    RestoreLiveRegisters(codegen, invoke_->GetLocations());
    __ B(GetExitLabel());
  }

 private:
  // The instruction where this slow path is happening.
  HInvoke* const invoke_;

  DISALLOW_COPY_AND_ASSIGN(IntrinsicSlowPathARM64);
};

#undef __

bool IntrinsicLocationsBuilderARM64::TryDispatch(HInvoke* invoke) {
  Dispatch(invoke);
  LocationSummary* res = invoke->GetLocations();
  return res != nullptr && res->Intrinsified();
}

#define __ masm->

/* add taint intrinsic funtion implementation */
/* Taint begin */

/*Integral type*/
// the general used AddTaint_LocationBuilder format
static void AddTaintLoc(ArenaAllocator* arena, HInvoke* invoke) {
        LocationSummary* locations = new (arena) LocationSummary(invoke,
                                                  LocationSummary::kCall,
                                                  kIntrinsified);
        locations->SetInAt(0, Location::RequiresRegister());
        locations->SetInAt(1, Location::RequiresRegister());
}

// the general used AddTaint_CodeGenerator function
static void AddTaintToTarget(LocationSummary* locations, bool isFloat, vixl::MacroAssembler* masm) {
    Location input0 = locations->InAt(0);
    Location input1 = locations->InAt(1);

    unsigned in_code = input0.reg();
    Register t_input = XRegisterFrom(input1);  // the register that contains taint.
    DCHECK(in_code != 63 && t_input.code() != 63);

    Register taint_str1 = Register::XRegFromCode(taint_code1);
    Register taint_str2 = Register::XRegFromCode(taint_code2);

    unsigned immr_bfm = 64 - 2 * in_code;
    unsigned imms_bfm = 1;
    if (isFloat) {
            __ Bfm(taint_str2, xzr, immr_bfm, imms_bfm);
            __ Orr(taint_str2, taint_str2, Operand(t_input, LSL, 2 * in_code));
    } else {
            __ Bfm(taint_str1, xzr, immr_bfm, imms_bfm);
            __ Orr(taint_str1, taint_str1, Operand(t_input, LSL, 2 * in_code));
    }
}

// the general VisitAddTaint format
void IntrinsicCodeGeneratorARM64::VisitTaintAddTaintInt(HInvoke* invoke) {
        vixl::MacroAssembler* masm = GetVIXLAssembler();
        LocationSummary* locations = invoke->GetLocations();

        AddTaintToTarget(locations, false, masm);
}

// the general used GetTaint_LocationBuilder format
static void GetTaintLoc(ArenaAllocator* arena, HInvoke* invoke) {
        LocationSummary* locations = new (arena) LocationSummary(invoke,
                                                  LocationSummary::kCall,
                                                  kIntrinsified);
        locations->SetInAt(0, Location::RequiresRegister());
        locations->SetOut(Location::RequiresRegister(), Location::kNoOutputOverlap);
}

// the general used GetTaint_CodeGenerator function
static void GetTaintFromTarget(LocationSummary* locations, bool isFloat, vixl::MacroAssembler* masm) {
        Location input = locations->InAt(0);
        Location output = locations->Out();

        unsigned in_code = input.reg();  // the number of register that contains the value that we need to find whether it has taint.
        Register t_out = XRegisterFrom(output);  // the register that contains the returned taint level
        DCHECK(in_code != 63 && t_out.code() != 63);

        Register taint_str1 = Register::XRegFromCode(taint_code1);
        Register taint_str2 = Register::XRegFromCode(taint_code2);

        unsigned lsb = 2 * in_code;  // the least significant bit,0-63
        unsigned width = 2;  // the width of the extracted bit field
        if (isFloat) {
                __ Ubfx(t_out, taint_str2, lsb, width);
        } else {
                __ Ubfx(t_out, taint_str1, lsb, width);
        }
}

// the general VisitGetTaint format
void IntrinsicCodeGeneratorARM64::VisitTaintGetTaintInt(HInvoke* invoke) {
        vixl::MacroAssembler* masm = GetVIXLAssembler();
        LocationSummary* locations = invoke->GetLocations();

        GetTaintFromTarget(locations, false, masm);
}

void IntrinsicLocationsBuilderARM64::VisitTaintAddTaintInt(HInvoke* invoke) { AddTaintLoc(arena_, invoke); }
void IntrinsicLocationsBuilderARM64::VisitTaintGetTaintInt(HInvoke* invoke) { GetTaintLoc(arena_, invoke); }

void IntrinsicLocationsBuilderARM64::VisitTaintAddTaintLong(HInvoke* invoke) { AddTaintLoc(arena_, invoke); }
void IntrinsicCodeGeneratorARM64::VisitTaintAddTaintLong(HInvoke* invoke) { VisitTaintAddTaintInt(invoke); }
void IntrinsicLocationsBuilderARM64::VisitTaintGetTaintLong(HInvoke* invoke) { GetTaintLoc(arena_, invoke); }
void IntrinsicCodeGeneratorARM64::VisitTaintGetTaintLong(HInvoke* invoke) { VisitTaintGetTaintInt(invoke); }

void IntrinsicLocationsBuilderARM64::VisitTaintAddTaintShort(HInvoke* invoke) { AddTaintLoc(arena_, invoke); }
void IntrinsicCodeGeneratorARM64::VisitTaintAddTaintShort(HInvoke* invoke) { VisitTaintAddTaintInt(invoke); }
void IntrinsicLocationsBuilderARM64::VisitTaintGetTaintShort(HInvoke* invoke) { GetTaintLoc(arena_, invoke); }
void IntrinsicCodeGeneratorARM64::VisitTaintGetTaintShort(HInvoke* invoke) { VisitTaintGetTaintInt(invoke); }

void IntrinsicLocationsBuilderARM64::VisitTaintAddTaintByte(HInvoke* invoke) { AddTaintLoc(arena_, invoke); }
void IntrinsicCodeGeneratorARM64::VisitTaintAddTaintByte(HInvoke* invoke) { VisitTaintAddTaintInt(invoke); }
void IntrinsicLocationsBuilderARM64::VisitTaintGetTaintByte(HInvoke* invoke) { GetTaintLoc(arena_, invoke); }
void IntrinsicCodeGeneratorARM64::VisitTaintGetTaintByte(HInvoke* invoke) { VisitTaintGetTaintInt(invoke); }

void IntrinsicLocationsBuilderARM64::VisitTaintAddTaintBoolean(HInvoke* invoke) { AddTaintLoc(arena_, invoke); }
void IntrinsicCodeGeneratorARM64::VisitTaintAddTaintBoolean(HInvoke* invoke) { VisitTaintAddTaintInt(invoke); }
void IntrinsicLocationsBuilderARM64::VisitTaintGetTaintBoolean(HInvoke* invoke) { GetTaintLoc(arena_, invoke); }
void IntrinsicCodeGeneratorARM64::VisitTaintGetTaintBoolean(HInvoke* invoke) { VisitTaintGetTaintInt(invoke); }

void IntrinsicLocationsBuilderARM64::VisitTaintGetTaintVoid(HInvoke* invoke) {
        LocationSummary* locations = new (arena_) LocationSummary(invoke,
                                                  LocationSummary::kCall,
                                                  kIntrinsified);
        locations->SetOut(Location::RequiresRegister(), Location::kNoOutputOverlap);
}
void IntrinsicCodeGeneratorARM64::VisitTaintGetTaintVoid(HInvoke* invoke) {
        LocationSummary* locations = invoke->GetLocations();
        vixl::MacroAssembler* masm = GetVIXLAssembler();

        Register t_out = XRegisterFrom(locations->Out());
        Register taint_str1 = Register::XRegFromCode(taint_code1);
        __ Mov(t_out, taint_str1);
}
/*
void IntrinsicLocationsBuilderARM64::VisitGetTaintVoidI(HInvoke* invoke){
	    LocationSummary* locations = new (arena_) LocationSummary(invoke,
															      LocationSummary::kCall,
																  kIntrinsified);
		locations->SetOut(Location::RequiresRegister(), Location::kNoOutputOverlap);
}
void IntrinsicLocationsBuilderARM64::VisitGetTaintVoidF(HInvoke* invoke){
	LocationSummary* locations = new (arena_) LocationSummary(invoke,
															  LocationSummary::kCall,
															  kIntrinsified);
	locations->SetOut(Location::RequiresRegister(), Location::kNoOutputOverlap);
}
/output all GPR taint
void IntrinsicCodeGeneratorARM64::VisitGetTaintVoidI(HInvoke* invoke){
	LocationSummary* locations = invoke->GetLocations();
	vixl::MacroAssembler* masm = GetVIXLAssembler();

	Register t_out = XRegisterFrom(locations->out());
	Register taint_str1 = Register::XRegisterFromCode(taint_code1);
	__ Mov(t_out, taint_str1);
}
/output all float register taint
void IntrinsicCodeGeneratorARM64::VisitGetTaintVoidF(HInvoke* invoke){
	LocationSummary* locations = invoke->GetLocations();
	vixl::MacroAssembler* masm = GetVIXLAssembler();

	Register t_out = XRegisterFrom(locations->out());
	Register taint_str2 = Register::XRegisterFromCode(taint_code2);
	__ Mov(t_out, taint_str2);
}
*/


/*Array type*/
void IntrinsicLocationsBuilderARM64::VisitTaintAddTaintIntArray(HInvoke* invoke) {
        LocationSummary* locations = new (arena_) LocationSummary(invoke,
                                                  LocationSummary::kCall,
                                                  kIntrinsified);
        locations->SetInAt(0, Location::RequiresRegister());
        locations->SetInAt(1, Location::RequiresRegister());
        locations->SetOut(Location::RequiresRegister(), Location::kNoOutputOverlap);
}

void IntrinsicLocationsBuilderARM64::VisitTaintGetTaintIntArray(HInvoke* invoke) { VisitTaintGetTaintInt(invoke); }

void IntrinsicCodeGeneratorARM64::VisitTaintAddTaintIntArray(HInvoke* invoke) {
        vixl::MacroAssembler* masm = GetVIXLAssembler();
        LocationSummary* locations = invoke->GetLocations();

        Location input1 = locations->InAt(1);
        Location output = locations->Out();

        unsigned out_code = output.reg();
        Register t_input = XRegisterFrom(input1);  // the register that contains taint.
        DCHECK(out_code != 63 && t_input.code() != 63);

        Register taint_str = Register::XRegFromCode(taint_code1);

        unsigned immr_bfm = 64 - 2 * out_code;
        unsigned imms_bfm = 1;
        __ Bfm(taint_str, xzr, immr_bfm, imms_bfm);
        __ Orr(taint_str, taint_str, Operand(t_input, LSL, 2 * out_code));

        // move the value in parameter 0 to the returned register
        __ Mov(XRegisterFrom(locations->Out()), XRegisterFrom(locations->InAt(0)));
}

void IntrinsicCodeGeneratorARM64::VisitTaintGetTaintIntArray(HInvoke* invoke) { VisitTaintGetTaintInt(invoke); }

/**
void IntrinsicLocationsBuilderARM64::VisitTaintGetTaintIntArray(HInvoke* invoke) {
        LocationSummary* locations = new (arena_) LocationSummary(invoke,
                                                  LocationSummary::kCall,
                                                  kIntrinsified);
        locations->SetInAt(0, Location::RequiresRegister());
        locations->SetOut(Location::RequiresRegister(), Location::kNoOutputOverlap);
}
// TODO
void IntrinsicCodeGeneratorARM64::VisitTaintGetTaintIntArray(HInvoke* invoke) {
        vixl::MacroAssembler* masm = GetVIXLAssembler();
        LocationSummary* locations = invoke->GetLocations();
        GetTaintFromTarget(locations, false, masm);
}
*/

#define VISIT_TAINT_INTRINSIC(type, visit_add_taint, visit_get_taint)  \
        void IntrinsicLocationsBuilderARM64::VisitTaintAddTaint ## type(HInvoke* invoke) {visit_add_taint(invoke);}  \
void IntrinsicCodeGeneratorARM64::VisitTaintAddTaint ## type(HInvoke* invoke) {visit_add_taint(invoke);}  \
void IntrinsicLocationsBuilderARM64::VisitTaintGetTaint ## type(HInvoke* invoke) {visit_get_taint(invoke);}  \
void IntrinsicCodeGeneratorARM64::VisitTaintGetTaint ## type(HInvoke* invoke) {visit_get_taint(invoke);}
VISIT_TAINT_INTRINSIC(ByteArray, VisitTaintAddTaintIntArray, VisitTaintGetTaintIntArray)
VISIT_TAINT_INTRINSIC(ShortArray, VisitTaintAddTaintIntArray, VisitTaintGetTaintIntArray)
VISIT_TAINT_INTRINSIC(BooleanArray, VisitTaintAddTaintIntArray, VisitTaintGetTaintIntArray)
VISIT_TAINT_INTRINSIC(CharArray, VisitTaintAddTaintIntArray, VisitTaintGetTaintIntArray)
VISIT_TAINT_INTRINSIC(LongArray, VisitTaintAddTaintIntArray, VisitTaintGetTaintIntArray)

/*Taint end*/

/*-------------Taint end--------------------------*/

static void CreateFPToIntLocations(ArenaAllocator* arena, HInvoke* invoke) {
  LocationSummary* locations = new (arena) LocationSummary(invoke,
                                                           LocationSummary::kNoCall,
                                                           kIntrinsified);
  locations->SetInAt(0, Location::RequiresFpuRegister());
  locations->SetOut(Location::RequiresRegister());
}

static void CreateIntToFPLocations(ArenaAllocator* arena, HInvoke* invoke) {
  LocationSummary* locations = new (arena) LocationSummary(invoke,
                                                           LocationSummary::kNoCall,
                                                           kIntrinsified);
  locations->SetInAt(0, Location::RequiresRegister());
  locations->SetOut(Location::RequiresFpuRegister());
}

#define MOVE_TAINT(taint_str1, taint_str2, code1, code2)  \
__ Mov(temp, 0);  \
if ( code2 == 0 )  \
__ Bfm(taint_str1, temp, 0, 1);  \
else  \
__ Bfm(taint_str1, temp, 64 - 2 * code2, 1);  \
__ Ubfm(temp, taint_str2, code1 * 2, code1 * 2 + 1);   \
__ Orr(taint_str1, taint_str1, Operand(temp, LSL, 2 * code2));

static void MoveFPToInt(LocationSummary* locations, bool is64bit, vixl::MacroAssembler* masm) {
  Location input = locations->InAt(0);
  Location output = locations->Out();
  __ Fmov(is64bit ? XRegisterFrom(output) : WRegisterFrom(output),
          is64bit ? DRegisterFrom(input) : SRegisterFrom(input));
  // Taint
  Register taint_str1 = Register::XRegFromCode(taint_code1);
  Register taint_str2 = Register::XRegFromCode(taint_code2);
  UseScratchRegisterScope temps(masm);

  Register temp = temps.AcquireX();
  unsigned out_code = XRegisterFrom(output).code();
  unsigned in_code = DRegisterFrom(input).code();
  MOVE_TAINT(taint_str1, taint_str2, in_code, out_code)
  // Taint
}

static void MoveIntToFP(LocationSummary* locations, bool is64bit, vixl::MacroAssembler* masm) {
  Location input = locations->InAt(0);
  Location output = locations->Out();
  __ Fmov(is64bit ? DRegisterFrom(output) : SRegisterFrom(output),
          is64bit ? XRegisterFrom(input) : WRegisterFrom(input));

  // Taint
  Register taint_str1 = Register::XRegFromCode(taint_code1);
  Register taint_str2 = Register::XRegFromCode(taint_code2);
  UseScratchRegisterScope temps(masm);

  Register temp = temps.AcquireX();
  unsigned out_code = DRegisterFrom(output).code();
  unsigned in_code = XRegisterFrom(input).code();
  MOVE_TAINT(taint_str2, taint_str1, in_code, out_code)
  // Taint
}

void IntrinsicLocationsBuilderARM64::VisitDoubleDoubleToRawLongBits(HInvoke* invoke) {
  CreateFPToIntLocations(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitDoubleLongBitsToDouble(HInvoke* invoke) {
  CreateIntToFPLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitDoubleDoubleToRawLongBits(HInvoke* invoke) {
  MoveFPToInt(invoke->GetLocations(), true, GetVIXLAssembler());
}
void IntrinsicCodeGeneratorARM64::VisitDoubleLongBitsToDouble(HInvoke* invoke) {
  MoveIntToFP(invoke->GetLocations(), true, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitFloatFloatToRawIntBits(HInvoke* invoke) {
  CreateFPToIntLocations(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitFloatIntBitsToFloat(HInvoke* invoke) {
  CreateIntToFPLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitFloatFloatToRawIntBits(HInvoke* invoke) {
  MoveFPToInt(invoke->GetLocations(), false, GetVIXLAssembler());
}
void IntrinsicCodeGeneratorARM64::VisitFloatIntBitsToFloat(HInvoke* invoke) {
  MoveIntToFP(invoke->GetLocations(), false, GetVIXLAssembler());
}

static void CreateIntToIntLocations(ArenaAllocator* arena, HInvoke* invoke) {
  LocationSummary* locations = new (arena) LocationSummary(invoke,
                                                           LocationSummary::kNoCall,
                                                           kIntrinsified);
  locations->SetInAt(0, Location::RequiresRegister());
  locations->SetOut(Location::RequiresRegister(), Location::kNoOutputOverlap);
}

static void GenReverseBytes(LocationSummary* locations,
                            Primitive::Type type,
                            vixl::MacroAssembler* masm) {
  Location in = locations->InAt(0);
  Location out = locations->Out();

  switch (type) {
    case Primitive::kPrimShort:
      __ Rev16(WRegisterFrom(out), WRegisterFrom(in));
      __ Sxth(WRegisterFrom(out), WRegisterFrom(out));
      break;
    case Primitive::kPrimInt:
    case Primitive::kPrimLong:
      __ Rev(RegisterFrom(out, type), RegisterFrom(in, type));
      break;
    default:
      LOG(FATAL) << "Unexpected size for reverse-bytes: " << type;
      UNREACHABLE();
  }
  // Taint: reverseBytes that means the taint tag of 'in' moves to 'out'
  Register taint_str = Register::XRegFromCode(taint_code1);
  UseScratchRegisterScope temps(masm);

  Register temp = temps.AcquireX();
  unsigned in_code = XRegisterFrom(in).code();
  unsigned out_code = XRegisterFrom(out).code();

  MOVE_TAINT(taint_str, taint_str, in_code, out_code)
  // Taint
}

void IntrinsicLocationsBuilderARM64::VisitIntegerReverseBytes(HInvoke* invoke) {
  CreateIntToIntLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitIntegerReverseBytes(HInvoke* invoke) {
  GenReverseBytes(invoke->GetLocations(), Primitive::kPrimInt, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitLongReverseBytes(HInvoke* invoke) {
  CreateIntToIntLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitLongReverseBytes(HInvoke* invoke) {
  GenReverseBytes(invoke->GetLocations(), Primitive::kPrimLong, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitShortReverseBytes(HInvoke* invoke) {
  CreateIntToIntLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitShortReverseBytes(HInvoke* invoke) {
  GenReverseBytes(invoke->GetLocations(), Primitive::kPrimShort, GetVIXLAssembler());
}

static void GenReverse(LocationSummary* locations,
                       Primitive::Type type,
                       vixl::MacroAssembler* masm) {
  DCHECK(type == Primitive::kPrimInt || type == Primitive::kPrimLong);

  Location in = locations->InAt(0);
  Location out = locations->Out();

  __ Rbit(RegisterFrom(out, type), RegisterFrom(in, type));

  // Taint: Reverse bits in GPR
  Register taint_str = Register::XRegFromCode(taint_code1);
  UseScratchRegisterScope temps(masm);

  Register temp = temps.AcquireX();
  unsigned in_code = XRegisterFrom(in).code();
  unsigned out_code = XRegisterFrom(out).code();

  MOVE_TAINT(taint_str, taint_str, in_code, out_code)
  // Taint
}

void IntrinsicLocationsBuilderARM64::VisitIntegerReverse(HInvoke* invoke) {
  CreateIntToIntLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitIntegerReverse(HInvoke* invoke) {
  GenReverse(invoke->GetLocations(), Primitive::kPrimInt, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitLongReverse(HInvoke* invoke) {
  CreateIntToIntLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitLongReverse(HInvoke* invoke) {
  GenReverse(invoke->GetLocations(), Primitive::kPrimLong, GetVIXLAssembler());
}

static void CreateFPToFPLocations(ArenaAllocator* arena, HInvoke* invoke) {
  LocationSummary* locations = new (arena) LocationSummary(invoke,
                                                           LocationSummary::kNoCall,
                                                           kIntrinsified);
  locations->SetInAt(0, Location::RequiresFpuRegister());
  locations->SetOut(Location::RequiresFpuRegister(), Location::kNoOutputOverlap);
}

static void MathAbsFP(LocationSummary* locations, bool is64bit, vixl::MacroAssembler* masm) {
  Location in = locations->InAt(0);
  Location out = locations->Out();

  FPRegister in_reg = is64bit ? DRegisterFrom(in) : SRegisterFrom(in);
  FPRegister out_reg = is64bit ? DRegisterFrom(out) : SRegisterFrom(out);

  __ Fabs(out_reg, in_reg);
  // Taint: Floating-point Absolute value
  Register taint_str = Register::XRegFromCode(taint_code2);
  UseScratchRegisterScope temps(masm);

  Register temp = temps.AcquireX();
  unsigned in_code = DRegisterFrom(in).code();
  unsigned out_code = DRegisterFrom(out).code();

  MOVE_TAINT(taint_str, taint_str, in_code, out_code)
  // Taint
}

void IntrinsicLocationsBuilderARM64::VisitMathAbsDouble(HInvoke* invoke) {
  CreateFPToFPLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathAbsDouble(HInvoke* invoke) {
  MathAbsFP(invoke->GetLocations(), true, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitMathAbsFloat(HInvoke* invoke) {
  CreateFPToFPLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathAbsFloat(HInvoke* invoke) {
  MathAbsFP(invoke->GetLocations(), false, GetVIXLAssembler());
}

static void CreateIntToInt(ArenaAllocator* arena, HInvoke* invoke) {
  LocationSummary* locations = new (arena) LocationSummary(invoke,
                                                           LocationSummary::kNoCall,
                                                           kIntrinsified);
  locations->SetInAt(0, Location::RequiresRegister());
  locations->SetOut(Location::RequiresRegister(), Location::kNoOutputOverlap);
}

static void GenAbsInteger(LocationSummary* locations,
                          bool is64bit,
                          vixl::MacroAssembler* masm) {
  Location in = locations->InAt(0);
  Location output = locations->Out();

  Register in_reg = is64bit ? XRegisterFrom(in) : WRegisterFrom(in);
  Register out_reg = is64bit ? XRegisterFrom(output) : WRegisterFrom(output);

  __ Cmp(in_reg, Operand(0));
  __ Cneg(out_reg, in_reg, lt);

  // Taint
  Register taint_str = Register::XRegFromCode(taint_code1);
  UseScratchRegisterScope temps(masm);

  Register temp = temps.AcquireX();
  unsigned in_code = in_reg.code();
  unsigned out_code = out_reg.code();

  MOVE_TAINT(taint_str, taint_str, in_code, out_code)
  // Taint
}

void IntrinsicLocationsBuilderARM64::VisitMathAbsInt(HInvoke* invoke) {
  CreateIntToInt(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathAbsInt(HInvoke* invoke) {
  GenAbsInteger(invoke->GetLocations(), false, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitMathAbsLong(HInvoke* invoke) {
  CreateIntToInt(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathAbsLong(HInvoke* invoke) {
  GenAbsInteger(invoke->GetLocations(), true, GetVIXLAssembler());
}

static void GenMinMaxFP(LocationSummary* locations,
                        bool is_min,
                        bool is_double,
                        vixl::MacroAssembler* masm) {
  Location op1 = locations->InAt(0);
  Location op2 = locations->InAt(1);
  Location out = locations->Out();

  FPRegister op1_reg = is_double ? DRegisterFrom(op1) : SRegisterFrom(op1);
  FPRegister op2_reg = is_double ? DRegisterFrom(op2) : SRegisterFrom(op2);
  FPRegister out_reg = is_double ? DRegisterFrom(out) : SRegisterFrom(out);
  if (is_min) {
    __ Fmin(out_reg, op1_reg, op2_reg);
  } else {
    __ Fmax(out_reg, op1_reg, op2_reg);
  }
}

static void CreateFPFPToFPLocations(ArenaAllocator* arena, HInvoke* invoke) {
  LocationSummary* locations = new (arena) LocationSummary(invoke,
                                                           LocationSummary::kNoCall,
                                                           kIntrinsified);
  locations->SetInAt(0, Location::RequiresFpuRegister());
  locations->SetInAt(1, Location::RequiresFpuRegister());
  locations->SetOut(Location::RequiresFpuRegister(), Location::kNoOutputOverlap);
}

void IntrinsicLocationsBuilderARM64::VisitMathMinDoubleDouble(HInvoke* invoke) {
  CreateFPFPToFPLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathMinDoubleDouble(HInvoke* invoke) {
  GenMinMaxFP(invoke->GetLocations(), true, true, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitMathMinFloatFloat(HInvoke* invoke) {
  CreateFPFPToFPLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathMinFloatFloat(HInvoke* invoke) {
  GenMinMaxFP(invoke->GetLocations(), true, false, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitMathMaxDoubleDouble(HInvoke* invoke) {
  CreateFPFPToFPLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathMaxDoubleDouble(HInvoke* invoke) {
  GenMinMaxFP(invoke->GetLocations(), false, true, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitMathMaxFloatFloat(HInvoke* invoke) {
  CreateFPFPToFPLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathMaxFloatFloat(HInvoke* invoke) {
  GenMinMaxFP(invoke->GetLocations(), false, false, GetVIXLAssembler());
}

static void GenMinMax(LocationSummary* locations,
                      bool is_min,
                      bool is_long,
                      vixl::MacroAssembler* masm) {
  Location op1 = locations->InAt(0);
  Location op2 = locations->InAt(1);
  Location out = locations->Out();

  Register op1_reg = is_long ? XRegisterFrom(op1) : WRegisterFrom(op1);
  Register op2_reg = is_long ? XRegisterFrom(op2) : WRegisterFrom(op2);
  Register out_reg = is_long ? XRegisterFrom(out) : WRegisterFrom(out);

  __ Cmp(op1_reg, op2_reg);
  __ Csel(out_reg, op1_reg, op2_reg, is_min ? lt : gt);
}

static void CreateIntIntToIntLocations(ArenaAllocator* arena, HInvoke* invoke) {
  LocationSummary* locations = new (arena) LocationSummary(invoke,
                                                           LocationSummary::kNoCall,
                                                           kIntrinsified);
  locations->SetInAt(0, Location::RequiresRegister());
  locations->SetInAt(1, Location::RequiresRegister());
  locations->SetOut(Location::RequiresRegister(), Location::kNoOutputOverlap);
}

void IntrinsicLocationsBuilderARM64::VisitMathMinIntInt(HInvoke* invoke) {
  CreateIntIntToIntLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathMinIntInt(HInvoke* invoke) {
  GenMinMax(invoke->GetLocations(), true, false, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitMathMinLongLong(HInvoke* invoke) {
  CreateIntIntToIntLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathMinLongLong(HInvoke* invoke) {
  GenMinMax(invoke->GetLocations(), true, true, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitMathMaxIntInt(HInvoke* invoke) {
  CreateIntIntToIntLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathMaxIntInt(HInvoke* invoke) {
  GenMinMax(invoke->GetLocations(), false, false, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitMathMaxLongLong(HInvoke* invoke) {
  CreateIntIntToIntLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathMaxLongLong(HInvoke* invoke) {
  GenMinMax(invoke->GetLocations(), false, true, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitMathSqrt(HInvoke* invoke) {
  CreateFPToFPLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathSqrt(HInvoke* invoke) {
  LocationSummary* locations = invoke->GetLocations();
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  __ Fsqrt(DRegisterFrom(locations->Out()), DRegisterFrom(locations->InAt(0)));
}

void IntrinsicLocationsBuilderARM64::VisitMathCeil(HInvoke* invoke) {
  CreateFPToFPLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathCeil(HInvoke* invoke) {
  LocationSummary* locations = invoke->GetLocations();
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  __ Frintp(DRegisterFrom(locations->Out()), DRegisterFrom(locations->InAt(0)));
}

void IntrinsicLocationsBuilderARM64::VisitMathFloor(HInvoke* invoke) {
  CreateFPToFPLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathFloor(HInvoke* invoke) {
  LocationSummary* locations = invoke->GetLocations();
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  __ Frintm(DRegisterFrom(locations->Out()), DRegisterFrom(locations->InAt(0)));
}

void IntrinsicLocationsBuilderARM64::VisitMathRint(HInvoke* invoke) {
  CreateFPToFPLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathRint(HInvoke* invoke) {
  LocationSummary* locations = invoke->GetLocations();
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  __ Frintn(DRegisterFrom(locations->Out()), DRegisterFrom(locations->InAt(0)));
}

static void CreateFPToIntPlusTempLocations(ArenaAllocator* arena, HInvoke* invoke) {
  LocationSummary* locations = new (arena) LocationSummary(invoke,
                                                           LocationSummary::kNoCall,
                                                           kIntrinsified);
  locations->SetInAt(0, Location::RequiresFpuRegister());
  locations->SetOut(Location::RequiresRegister());
}

static void GenMathRound(LocationSummary* locations,
                         bool is_double,
                         vixl::MacroAssembler* masm) {
  FPRegister in_reg = is_double ?
      DRegisterFrom(locations->InAt(0)) : SRegisterFrom(locations->InAt(0));
  Register out_reg = is_double ?
      XRegisterFrom(locations->Out()) : WRegisterFrom(locations->Out());
  UseScratchRegisterScope temps(masm);
  FPRegister temp1_reg = temps.AcquireSameSizeAs(in_reg);

  // 0.5 can be encoded as an immediate, so use fmov.
  if (is_double) {
    __ Fmov(temp1_reg, static_cast<double>(0.5));
  } else {
    __ Fmov(temp1_reg, static_cast<float>(0.5));
  }
  __ Fadd(temp1_reg, in_reg, temp1_reg);
  __ Fcvtms(out_reg, temp1_reg);

  // Taint: Floating-point Convert to Signed integer
  Register taint_str1 = Register::XRegFromCode(taint_code1);
  Register taint_str2 = Register::XRegFromCode(taint_code2);

  Register temp = temps.AcquireX();
  unsigned in_code = in_reg.code();
  unsigned out_code = out_reg.code();

  MOVE_TAINT(taint_str1, taint_str2, in_code, out_code)
  // Taint
}

void IntrinsicLocationsBuilderARM64::VisitMathRoundDouble(HInvoke* invoke) {
  CreateFPToIntPlusTempLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathRoundDouble(HInvoke* invoke) {
  GenMathRound(invoke->GetLocations(), true, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitMathRoundFloat(HInvoke* invoke) {
  CreateFPToIntPlusTempLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMathRoundFloat(HInvoke* invoke) {
  GenMathRound(invoke->GetLocations(), false, GetVIXLAssembler());
}

void IntrinsicLocationsBuilderARM64::VisitMemoryPeekByte(HInvoke* invoke) {
  CreateIntToIntLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMemoryPeekByte(HInvoke* invoke) {
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  __ Ldrsb(WRegisterFrom(invoke->GetLocations()->Out()),
          AbsoluteHeapOperandFrom(invoke->GetLocations()->InAt(0), 0));
  // TEST
  VLOG(TA64) << "The intrinsics completaion of PeekByte() in Memory.java";
}

void IntrinsicLocationsBuilderARM64::VisitMemoryPeekIntNative(HInvoke* invoke) {
  CreateIntToIntLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMemoryPeekIntNative(HInvoke* invoke) {
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  __ Ldr(WRegisterFrom(invoke->GetLocations()->Out()),
         AbsoluteHeapOperandFrom(invoke->GetLocations()->InAt(0), 0));
}

void IntrinsicLocationsBuilderARM64::VisitMemoryPeekLongNative(HInvoke* invoke) {
  CreateIntToIntLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMemoryPeekLongNative(HInvoke* invoke) {
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  __ Ldr(XRegisterFrom(invoke->GetLocations()->Out()),
         AbsoluteHeapOperandFrom(invoke->GetLocations()->InAt(0), 0));
}

void IntrinsicLocationsBuilderARM64::VisitMemoryPeekShortNative(HInvoke* invoke) {
  CreateIntToIntLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMemoryPeekShortNative(HInvoke* invoke) {
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  __ Ldrsh(WRegisterFrom(invoke->GetLocations()->Out()),
           AbsoluteHeapOperandFrom(invoke->GetLocations()->InAt(0), 0));
}

static void CreateIntIntToVoidLocations(ArenaAllocator* arena, HInvoke* invoke) {
  LocationSummary* locations = new (arena) LocationSummary(invoke,
                                                           LocationSummary::kNoCall,
                                                           kIntrinsified);
  locations->SetInAt(0, Location::RequiresRegister());
  locations->SetInAt(1, Location::RequiresRegister());
}

void IntrinsicLocationsBuilderARM64::VisitMemoryPokeByte(HInvoke* invoke) {
  CreateIntIntToVoidLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMemoryPokeByte(HInvoke* invoke) {
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  __ Strb(WRegisterFrom(invoke->GetLocations()->InAt(1)),
          AbsoluteHeapOperandFrom(invoke->GetLocations()->InAt(0), 0));
}

void IntrinsicLocationsBuilderARM64::VisitMemoryPokeIntNative(HInvoke* invoke) {
  CreateIntIntToVoidLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMemoryPokeIntNative(HInvoke* invoke) {
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  __ Str(WRegisterFrom(invoke->GetLocations()->InAt(1)),
         AbsoluteHeapOperandFrom(invoke->GetLocations()->InAt(0), 0));
}

void IntrinsicLocationsBuilderARM64::VisitMemoryPokeLongNative(HInvoke* invoke) {
  CreateIntIntToVoidLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMemoryPokeLongNative(HInvoke* invoke) {
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  __ Str(XRegisterFrom(invoke->GetLocations()->InAt(1)),
         AbsoluteHeapOperandFrom(invoke->GetLocations()->InAt(0), 0));
}

void IntrinsicLocationsBuilderARM64::VisitMemoryPokeShortNative(HInvoke* invoke) {
  CreateIntIntToVoidLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitMemoryPokeShortNative(HInvoke* invoke) {
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  __ Strh(WRegisterFrom(invoke->GetLocations()->InAt(1)),
          AbsoluteHeapOperandFrom(invoke->GetLocations()->InAt(0), 0));
}

void IntrinsicLocationsBuilderARM64::VisitThreadCurrentThread(HInvoke* invoke) {
  LocationSummary* locations = new (arena_) LocationSummary(invoke,
                                                            LocationSummary::kNoCall,
                                                            kIntrinsified);
  locations->SetOut(Location::RequiresRegister());
}

void IntrinsicCodeGeneratorARM64::VisitThreadCurrentThread(HInvoke* invoke) {
  codegen_->Load(Primitive::kPrimNot, WRegisterFrom(invoke->GetLocations()->Out()),
                 MemOperand(tr, Thread::PeerOffset<8>().Int32Value()));
}

static void GenUnsafeGet(HInvoke* invoke,
                         Primitive::Type type,
                         bool is_volatile,
                         CodeGeneratorARM64* codegen) {
  LocationSummary* locations = invoke->GetLocations();
  DCHECK((type == Primitive::kPrimInt) ||
         (type == Primitive::kPrimLong) ||
         (type == Primitive::kPrimNot));
  vixl::MacroAssembler* masm = codegen->GetAssembler()->vixl_masm_;
  Register base = WRegisterFrom(locations->InAt(1));    // Object pointer.
  Register offset = XRegisterFrom(locations->InAt(2));  // Long offset.
  Register trg = RegisterFrom(locations->Out(), type);
  bool use_acquire_release = codegen->GetInstructionSetFeatures().PreferAcquireRelease();

  MemOperand mem_op(base.X(), offset);
  if (is_volatile) {
    if (use_acquire_release) {
      codegen->LoadAcquire(invoke, trg, mem_op);
    } else {
      codegen->Load(type, trg, mem_op);
      __ Dmb(InnerShareable, BarrierReads);
    }
  } else {
    codegen->Load(type, trg, mem_op);
  }
}

static void CreateIntIntIntToIntLocations(ArenaAllocator* arena, HInvoke* invoke) {
  LocationSummary* locations = new (arena) LocationSummary(invoke,
                                                           LocationSummary::kNoCall,
                                                           kIntrinsified);
  locations->SetInAt(0, Location::NoLocation());        // Unused receiver.
  locations->SetInAt(1, Location::RequiresRegister());
  locations->SetInAt(2, Location::RequiresRegister());
  locations->SetOut(Location::RequiresRegister(), Location::kNoOutputOverlap);
}

void IntrinsicLocationsBuilderARM64::VisitUnsafeGet(HInvoke* invoke) {
  CreateIntIntIntToIntLocations(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafeGetVolatile(HInvoke* invoke) {
  CreateIntIntIntToIntLocations(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafeGetLong(HInvoke* invoke) {
  CreateIntIntIntToIntLocations(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafeGetLongVolatile(HInvoke* invoke) {
  CreateIntIntIntToIntLocations(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafeGetObject(HInvoke* invoke) {
  CreateIntIntIntToIntLocations(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafeGetObjectVolatile(HInvoke* invoke) {
  CreateIntIntIntToIntLocations(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitUnsafeGet(HInvoke* invoke) {
  GenUnsafeGet(invoke, Primitive::kPrimInt, false, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafeGetVolatile(HInvoke* invoke) {
  GenUnsafeGet(invoke, Primitive::kPrimInt, true, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafeGetLong(HInvoke* invoke) {
  GenUnsafeGet(invoke, Primitive::kPrimLong, false, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafeGetLongVolatile(HInvoke* invoke) {
  GenUnsafeGet(invoke, Primitive::kPrimLong, true, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafeGetObject(HInvoke* invoke) {
  GenUnsafeGet(invoke, Primitive::kPrimNot, false, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafeGetObjectVolatile(HInvoke* invoke) {
  GenUnsafeGet(invoke, Primitive::kPrimNot, true, codegen_);
}

static void CreateIntIntIntIntToVoid(ArenaAllocator* arena, HInvoke* invoke) {
  LocationSummary* locations = new (arena) LocationSummary(invoke,
                                                           LocationSummary::kNoCall,
                                                           kIntrinsified);
  locations->SetInAt(0, Location::NoLocation());        // Unused receiver.
  locations->SetInAt(1, Location::RequiresRegister());
  locations->SetInAt(2, Location::RequiresRegister());
  locations->SetInAt(3, Location::RequiresRegister());
}

void IntrinsicLocationsBuilderARM64::VisitUnsafePut(HInvoke* invoke) {
  CreateIntIntIntIntToVoid(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafePutOrdered(HInvoke* invoke) {
  CreateIntIntIntIntToVoid(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafePutVolatile(HInvoke* invoke) {
  CreateIntIntIntIntToVoid(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafePutObject(HInvoke* invoke) {
  CreateIntIntIntIntToVoid(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafePutObjectOrdered(HInvoke* invoke) {
  CreateIntIntIntIntToVoid(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafePutObjectVolatile(HInvoke* invoke) {
  CreateIntIntIntIntToVoid(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafePutLong(HInvoke* invoke) {
  CreateIntIntIntIntToVoid(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafePutLongOrdered(HInvoke* invoke) {
  CreateIntIntIntIntToVoid(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafePutLongVolatile(HInvoke* invoke) {
  CreateIntIntIntIntToVoid(arena_, invoke);
}

static void GenUnsafePut(LocationSummary* locations,
                         Primitive::Type type,
                         bool is_volatile,
                         bool is_ordered,
                         CodeGeneratorARM64* codegen) {
  vixl::MacroAssembler* masm = codegen->GetAssembler()->vixl_masm_;

  Register base = WRegisterFrom(locations->InAt(1));    // Object pointer.
  Register offset = XRegisterFrom(locations->InAt(2));  // Long offset.
  Register value = RegisterFrom(locations->InAt(3), type);
  bool use_acquire_release = codegen->GetInstructionSetFeatures().PreferAcquireRelease();

  MemOperand mem_op(base.X(), offset);

  if (is_volatile || is_ordered) {
    if (use_acquire_release) {
      codegen->StoreRelease(type, value, mem_op);
    } else {
      __ Dmb(InnerShareable, BarrierAll);
      codegen->Store(type, value, mem_op);
      if (is_volatile) {
        __ Dmb(InnerShareable, BarrierReads);
      }
    }
  } else {
    codegen->Store(type, value, mem_op);
  }

  if (type == Primitive::kPrimNot) {
    codegen->MarkGCCard(base, value);
  }
}

void IntrinsicCodeGeneratorARM64::VisitUnsafePut(HInvoke* invoke) {
  GenUnsafePut(invoke->GetLocations(), Primitive::kPrimInt, false, false, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafePutOrdered(HInvoke* invoke) {
  GenUnsafePut(invoke->GetLocations(), Primitive::kPrimInt, false, true, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafePutVolatile(HInvoke* invoke) {
  GenUnsafePut(invoke->GetLocations(), Primitive::kPrimInt, true, false, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafePutObject(HInvoke* invoke) {
  GenUnsafePut(invoke->GetLocations(), Primitive::kPrimNot, false, false, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafePutObjectOrdered(HInvoke* invoke) {
  GenUnsafePut(invoke->GetLocations(), Primitive::kPrimNot, false, true, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafePutObjectVolatile(HInvoke* invoke) {
  GenUnsafePut(invoke->GetLocations(), Primitive::kPrimNot, true, false, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafePutLong(HInvoke* invoke) {
  GenUnsafePut(invoke->GetLocations(), Primitive::kPrimLong, false, false, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafePutLongOrdered(HInvoke* invoke) {
  GenUnsafePut(invoke->GetLocations(), Primitive::kPrimLong, false, true, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafePutLongVolatile(HInvoke* invoke) {
  GenUnsafePut(invoke->GetLocations(), Primitive::kPrimLong, true, false, codegen_);
}

static void CreateIntIntIntIntIntToInt(ArenaAllocator* arena, HInvoke* invoke) {
  LocationSummary* locations = new (arena) LocationSummary(invoke,
                                                           LocationSummary::kNoCall,
                                                           kIntrinsified);
  locations->SetInAt(0, Location::NoLocation());        // Unused receiver.
  locations->SetInAt(1, Location::RequiresRegister());
  locations->SetInAt(2, Location::RequiresRegister());
  locations->SetInAt(3, Location::RequiresRegister());
  locations->SetInAt(4, Location::RequiresRegister());

  locations->SetOut(Location::RequiresRegister(), Location::kNoOutputOverlap);
}

static void GenCas(LocationSummary* locations, Primitive::Type type, CodeGeneratorARM64* codegen) {
  bool use_acquire_release = codegen->GetInstructionSetFeatures().PreferAcquireRelease();
  vixl::MacroAssembler* masm = codegen->GetAssembler()->vixl_masm_;

  Register out = WRegisterFrom(locations->Out());                  // Boolean result.

  Register base = WRegisterFrom(locations->InAt(1));               // Object pointer.
  Register offset = XRegisterFrom(locations->InAt(2));             // Long offset.
  Register expected = RegisterFrom(locations->InAt(3), type);      // Expected.
  Register value = RegisterFrom(locations->InAt(4), type);         // Value.

  // This needs to be before the temp registers, as MarkGCCard also uses VIXL temps.
  if (type == Primitive::kPrimNot) {
    // Mark card for object assuming new value is stored.
    codegen->MarkGCCard(base, value);
  }

  UseScratchRegisterScope temps(masm);
  Register tmp_ptr = temps.AcquireX();                             // Pointer to actual memory.
  Register tmp_value = temps.AcquireSameSizeAs(value);             // Value in memory.

  Register tmp_32 = tmp_value.W();

  __ Add(tmp_ptr, base.X(), Operand(offset));

  // do {
  //   tmp_value = [tmp_ptr] - expected;
  // } while (tmp_value == 0 && failure([tmp_ptr] <- r_new_value));
  // result = tmp_value != 0;

  vixl::Label loop_head, exit_loop;
  if (use_acquire_release) {
    __ Bind(&loop_head);
    __ Ldaxr(tmp_value, MemOperand(tmp_ptr));
    __ Cmp(tmp_value, expected);
    __ B(&exit_loop, ne);
    __ Stlxr(tmp_32, value, MemOperand(tmp_ptr));
    __ Cbnz(tmp_32, &loop_head);
  } else {
    __ Dmb(InnerShareable, BarrierWrites);
    __ Bind(&loop_head);
    __ Ldxr(tmp_value, MemOperand(tmp_ptr));
    __ Cmp(tmp_value, expected);
    __ B(&exit_loop, ne);
    __ Stxr(tmp_32, value, MemOperand(tmp_ptr));
    __ Cbnz(tmp_32, &loop_head);
    __ Dmb(InnerShareable, BarrierAll);
  }
  __ Bind(&exit_loop);
  __ Cset(out, eq);
}

void IntrinsicLocationsBuilderARM64::VisitUnsafeCASInt(HInvoke* invoke) {
  CreateIntIntIntIntIntToInt(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafeCASLong(HInvoke* invoke) {
  CreateIntIntIntIntIntToInt(arena_, invoke);
}
void IntrinsicLocationsBuilderARM64::VisitUnsafeCASObject(HInvoke* invoke) {
  CreateIntIntIntIntIntToInt(arena_, invoke);
}

void IntrinsicCodeGeneratorARM64::VisitUnsafeCASInt(HInvoke* invoke) {
  GenCas(invoke->GetLocations(), Primitive::kPrimInt, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafeCASLong(HInvoke* invoke) {
  GenCas(invoke->GetLocations(), Primitive::kPrimLong, codegen_);
}
void IntrinsicCodeGeneratorARM64::VisitUnsafeCASObject(HInvoke* invoke) {
  GenCas(invoke->GetLocations(), Primitive::kPrimNot, codegen_);
}

void IntrinsicLocationsBuilderARM64::VisitStringCharAt(HInvoke* invoke) {
  LocationSummary* locations = new (arena_) LocationSummary(invoke,
                                                            LocationSummary::kCallOnSlowPath,
                                                            kIntrinsified);
  locations->SetInAt(0, Location::RequiresRegister());
  locations->SetInAt(1, Location::RequiresRegister());
  // In case we need to go in the slow path, we can't have the output be the same
  // as the input: the current liveness analysis considers the input to be live
  // at the point of the call.
  locations->SetOut(Location::RequiresRegister(), Location::kOutputOverlap);
}

void IntrinsicCodeGeneratorARM64::VisitStringCharAt(HInvoke* invoke) {
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  LocationSummary* locations = invoke->GetLocations();

  // Location of reference to data array
  const MemberOffset value_offset = mirror::String::ValueOffset();
  // Location of count
  const MemberOffset count_offset = mirror::String::CountOffset();

  Register obj = WRegisterFrom(locations->InAt(0));  // String object pointer.
  Register idx = WRegisterFrom(locations->InAt(1));  // Index of character.
  Register out = WRegisterFrom(locations->Out());    // Result character.

  UseScratchRegisterScope temps(masm);
  Register temp = temps.AcquireW();
  Register array_temp = temps.AcquireW();            // We can trade this for worse scheduling.

  // TODO: Maybe we can support range check elimination. Overall, though, I think it's not worth
  //       the cost.
  // TODO: For simplicity, the index parameter is requested in a register, so different from Quick
  //       we will not optimize the code for constants (which would save a register).

  SlowPathCodeARM64* slow_path = new (GetAllocator()) IntrinsicSlowPathARM64(invoke);
  codegen_->AddSlowPath(slow_path);

  __ Ldr(temp, HeapOperand(obj, count_offset));          // temp = str.length.
  codegen_->MaybeRecordImplicitNullCheck(invoke);
  __ Cmp(idx, temp);
  __ B(hs, slow_path->GetEntryLabel());

  __ Add(array_temp, obj, Operand(value_offset.Int32Value()));  // array_temp := str.value.

  // Load the value.
  __ Ldrh(out, MemOperand(array_temp.X(), idx, UXTW, 1));  // out := array_temp[idx].

  __ Bind(slow_path->GetExitLabel());
}

void IntrinsicLocationsBuilderARM64::VisitStringCompareTo(HInvoke* invoke) {
  LocationSummary* locations = new (arena_) LocationSummary(invoke,
                                                            LocationSummary::kCall,
                                                            kIntrinsified);
  InvokeRuntimeCallingConvention calling_convention;
  locations->SetInAt(0, LocationFrom(calling_convention.GetRegisterAt(0)));
  locations->SetInAt(1, LocationFrom(calling_convention.GetRegisterAt(1)));
  locations->SetOut(calling_convention.GetReturnLocation(Primitive::kPrimInt));
}

void IntrinsicCodeGeneratorARM64::VisitStringCompareTo(HInvoke* invoke) {
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  LocationSummary* locations = invoke->GetLocations();

  // Note that the null check must have been done earlier.
  DCHECK(!invoke->CanDoImplicitNullCheckOn(invoke->InputAt(0)));

  Register argument = WRegisterFrom(locations->InAt(1));
  __ Cmp(argument, 0);
  SlowPathCodeARM64* slow_path = new (GetAllocator()) IntrinsicSlowPathARM64(invoke);
  codegen_->AddSlowPath(slow_path);
  __ B(eq, slow_path->GetEntryLabel());

  __ Ldr(
      lr, MemOperand(tr, QUICK_ENTRYPOINT_OFFSET(kArm64WordSize, pStringCompareTo).Int32Value()));
  __ Blr(lr);
  __ Bind(slow_path->GetExitLabel());
}

static void GenerateVisitStringIndexOf(HInvoke* invoke,
                                       vixl::MacroAssembler* masm,
                                       CodeGeneratorARM64* codegen,
                                       ArenaAllocator* allocator,
                                       bool start_at_zero) {
  LocationSummary* locations = invoke->GetLocations();
  Register tmp_reg = WRegisterFrom(locations->GetTemp(0));

  // Note that the null check must have been done earlier.
  DCHECK(!invoke->CanDoImplicitNullCheckOn(invoke->InputAt(0)));

  // Check for code points > 0xFFFF. Either a slow-path check when we don't know statically,
  // or directly dispatch if we have a constant.
  SlowPathCodeARM64* slow_path = nullptr;
  if (invoke->InputAt(1)->IsIntConstant()) {
    if (static_cast<uint32_t>(invoke->InputAt(1)->AsIntConstant()->GetValue()) > 0xFFFFU) {
      // Always needs the slow-path. We could directly dispatch to it, but this case should be
      // rare, so for simplicity just put the full slow-path down and branch unconditionally.
      slow_path = new (allocator) IntrinsicSlowPathARM64(invoke);
      codegen->AddSlowPath(slow_path);
      __ B(slow_path->GetEntryLabel());
      __ Bind(slow_path->GetExitLabel());
      return;
    }
  } else {
    Register char_reg = WRegisterFrom(locations->InAt(1));
    __ Mov(tmp_reg, 0xFFFF);
    __ Cmp(char_reg, Operand(tmp_reg));
    slow_path = new (allocator) IntrinsicSlowPathARM64(invoke);
    codegen->AddSlowPath(slow_path);
    __ B(hi, slow_path->GetEntryLabel());
  }

  if (start_at_zero) {
    // Start-index = 0.
    __ Mov(tmp_reg, 0);
  }

  __ Ldr(lr, MemOperand(tr, QUICK_ENTRYPOINT_OFFSET(kArm64WordSize, pIndexOf).Int32Value()));
  __ Blr(lr);

  if (slow_path != nullptr) {
    __ Bind(slow_path->GetExitLabel());
  }
}

void IntrinsicLocationsBuilderARM64::VisitStringIndexOf(HInvoke* invoke) {
  LocationSummary* locations = new (arena_) LocationSummary(invoke,
                                                            LocationSummary::kCall,
                                                            kIntrinsified);
  // We have a hand-crafted assembly stub that follows the runtime calling convention. So it's
  // best to align the inputs accordingly.
  InvokeRuntimeCallingConvention calling_convention;
  locations->SetInAt(0, LocationFrom(calling_convention.GetRegisterAt(0)));
  locations->SetInAt(1, LocationFrom(calling_convention.GetRegisterAt(1)));
  locations->SetOut(calling_convention.GetReturnLocation(Primitive::kPrimInt));

  // Need a temp for slow-path codepoint compare, and need to send start_index=0.
  locations->AddTemp(LocationFrom(calling_convention.GetRegisterAt(2)));
}

void IntrinsicCodeGeneratorARM64::VisitStringIndexOf(HInvoke* invoke) {
  GenerateVisitStringIndexOf(invoke, GetVIXLAssembler(), codegen_, GetAllocator(), true);
}

void IntrinsicLocationsBuilderARM64::VisitStringIndexOfAfter(HInvoke* invoke) {
  LocationSummary* locations = new (arena_) LocationSummary(invoke,
                                                            LocationSummary::kCall,
                                                            kIntrinsified);
  // We have a hand-crafted assembly stub that follows the runtime calling convention. So it's
  // best to align the inputs accordingly.
  InvokeRuntimeCallingConvention calling_convention;
  locations->SetInAt(0, LocationFrom(calling_convention.GetRegisterAt(0)));
  locations->SetInAt(1, LocationFrom(calling_convention.GetRegisterAt(1)));
  locations->SetInAt(2, LocationFrom(calling_convention.GetRegisterAt(2)));
  locations->SetOut(calling_convention.GetReturnLocation(Primitive::kPrimInt));

  // Need a temp for slow-path codepoint compare.
  locations->AddTemp(Location::RequiresRegister());
}

void IntrinsicCodeGeneratorARM64::VisitStringIndexOfAfter(HInvoke* invoke) {
  GenerateVisitStringIndexOf(invoke, GetVIXLAssembler(), codegen_, GetAllocator(), false);
}

void IntrinsicLocationsBuilderARM64::VisitStringNewStringFromBytes(HInvoke* invoke) {
  LocationSummary* locations = new (arena_) LocationSummary(invoke,
                                                            LocationSummary::kCall,
                                                            kIntrinsified);
  InvokeRuntimeCallingConvention calling_convention;
  locations->SetInAt(0, LocationFrom(calling_convention.GetRegisterAt(0)));
  locations->SetInAt(1, LocationFrom(calling_convention.GetRegisterAt(1)));
  locations->SetInAt(2, LocationFrom(calling_convention.GetRegisterAt(2)));
  locations->SetInAt(3, LocationFrom(calling_convention.GetRegisterAt(3)));
  locations->SetOut(calling_convention.GetReturnLocation(Primitive::kPrimNot));
}

void IntrinsicCodeGeneratorARM64::VisitStringNewStringFromBytes(HInvoke* invoke) {
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  LocationSummary* locations = invoke->GetLocations();

  Register byte_array = WRegisterFrom(locations->InAt(0));
  __ Cmp(byte_array, 0);
  SlowPathCodeARM64* slow_path = new (GetAllocator()) IntrinsicSlowPathARM64(invoke);
  codegen_->AddSlowPath(slow_path);
  __ B(eq, slow_path->GetEntryLabel());

  __ Ldr(lr,
      MemOperand(tr, QUICK_ENTRYPOINT_OFFSET(kArm64WordSize, pAllocStringFromBytes).Int32Value()));
  codegen_->RecordPcInfo(invoke, invoke->GetDexPc());
  __ Blr(lr);
  __ Bind(slow_path->GetExitLabel());
}

void IntrinsicLocationsBuilderARM64::VisitStringNewStringFromChars(HInvoke* invoke) {
  LocationSummary* locations = new (arena_) LocationSummary(invoke,
                                                            LocationSummary::kCall,
                                                            kIntrinsified);
  InvokeRuntimeCallingConvention calling_convention;
  locations->SetInAt(0, LocationFrom(calling_convention.GetRegisterAt(0)));
  locations->SetInAt(1, LocationFrom(calling_convention.GetRegisterAt(1)));
  locations->SetInAt(2, LocationFrom(calling_convention.GetRegisterAt(2)));
  locations->SetOut(calling_convention.GetReturnLocation(Primitive::kPrimNot));
}

void IntrinsicCodeGeneratorARM64::VisitStringNewStringFromChars(HInvoke* invoke) {
  vixl::MacroAssembler* masm = GetVIXLAssembler();

  __ Ldr(lr,
      MemOperand(tr, QUICK_ENTRYPOINT_OFFSET(kArm64WordSize, pAllocStringFromChars).Int32Value()));
  codegen_->RecordPcInfo(invoke, invoke->GetDexPc());
  __ Blr(lr);
}

void IntrinsicLocationsBuilderARM64::VisitStringNewStringFromString(HInvoke* invoke) {
  // The inputs plus one temp.
  LocationSummary* locations = new (arena_) LocationSummary(invoke,
                                                            LocationSummary::kCall,
                                                            kIntrinsified);
  InvokeRuntimeCallingConvention calling_convention;
  locations->SetInAt(0, LocationFrom(calling_convention.GetRegisterAt(0)));
  locations->SetInAt(1, LocationFrom(calling_convention.GetRegisterAt(1)));
  locations->SetInAt(2, LocationFrom(calling_convention.GetRegisterAt(2)));
  locations->SetOut(calling_convention.GetReturnLocation(Primitive::kPrimNot));
}

void IntrinsicCodeGeneratorARM64::VisitStringNewStringFromString(HInvoke* invoke) {
  vixl::MacroAssembler* masm = GetVIXLAssembler();
  LocationSummary* locations = invoke->GetLocations();

  Register string_to_copy = WRegisterFrom(locations->InAt(0));
  __ Cmp(string_to_copy, 0);
  SlowPathCodeARM64* slow_path = new (GetAllocator()) IntrinsicSlowPathARM64(invoke);
  codegen_->AddSlowPath(slow_path);
  __ B(eq, slow_path->GetEntryLabel());

  __ Ldr(lr,
      MemOperand(tr, QUICK_ENTRYPOINT_OFFSET(kArm64WordSize, pAllocStringFromString).Int32Value()));
  codegen_->RecordPcInfo(invoke, invoke->GetDexPc());
  __ Blr(lr);
  __ Bind(slow_path->GetExitLabel());
}

// Unimplemented intrinsics.

#define UNIMPLEMENTED_INTRINSIC(Name)                                                  \
void IntrinsicLocationsBuilderARM64::Visit ## Name(HInvoke* invoke ATTRIBUTE_UNUSED) { \
}                                                                                      \
void IntrinsicCodeGeneratorARM64::Visit ## Name(HInvoke* invoke ATTRIBUTE_UNUSED) {    \
}

UNIMPLEMENTED_INTRINSIC(SystemArrayCopyChar)
UNIMPLEMENTED_INTRINSIC(ReferenceGetReferent)
UNIMPLEMENTED_INTRINSIC(StringGetCharsNoCheck)

}  // namespace arm64
}  // namespace art
