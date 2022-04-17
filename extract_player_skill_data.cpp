#include <cassert>
#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>

#include "battle/guestSkill.h"

int main() {
    std::ifstream ifs("baserom.gba", std::ios::binary);
    ifs.seekg(0xcf728);

    std::ofstream ofx("playerSkillData.cpp", std::ios::binary);

    std::vector<GuestSkillInfo> data;
    assert(sizeof(GuestSkillInfo) == 44);

    auto printField = [&](long value) -> std::string {
        std::stringstream ss;
        ss << std::hex << "\t0x" << value << ",";
        return ss.str();
    };

    for (int i = 0; i < 64; i++) {
        GuestSkillInfo m;
        ifs.read((char*)&m, sizeof(GuestSkillInfo));
        data.emplace_back(m);
    }

    ofx << "const GuestSkillInfo gPlayerSkillData[] = {" << std::endl;
    for (auto& m : data) {
        ofx << "{";
        ofx << " /*      ID */" << printField(m.id);
        ofx << " /*  EFFECT */" << printField(m.move.effect);
        ofx << " /* ELEMENT */" << printField(m.move.element);
        ofx << " /*  TARGET */" << printField(m.move.target);
        ofx << " /*    UNK1 */" << printField(m.move.unk1);
        ofx << " /* ATK MUL */" << printField(m.move.atk_mult);
        ofx << " /* HEAL LO */" << printField(m.move.heal_lo);
        ofx << " /* HEAL HI */" << printField(m.move.heal_hi);
        ofx << " /*  STATUS */" << printField(m.move.ailment);
        ofx << " /* STATUS% */" << printField(m.move.ailment_chance);
        ofx << " /*  ACTION */" << printField(m.move.action);
        ofx << " /*    PRIO */" << printField(m.move.priority);
        ofx << " /*  MSG NO */" << printField(m.move.msg_no);
        ofx << " /* DIMMING */" << printField(m.move.has_dim);
        ofx << " /*  SEQ NO */" << printField(m.move.anim_no);
        ofx << " /* SEQ NO2 */" << printField(m.move.anim_success);
        ofx << " /*   SOUND */" << printField(m.move.sfx_no);
        ofx << " /*  MISS % */" << printField(m.move.miss_chance);
        ofx << " /* SMASH % */" << printField(m.move.smash_chance);
        ofx << " /* REDIR 1 */" << printField(m.move.redirectable);
        ofx << " /* REDIR 2 */" << printField(m.move.redirectable2);
        // ofx << "},";
        ofx << "}," << std::endl;
    }
    ofx << "};" << std::endl;

    return 0;
}
