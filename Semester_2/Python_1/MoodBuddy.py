"""
MoodBuddy — Complete Emotion Tracking
-------------------------------------------------
A persistent beginner Python mood tracker.

The program saves one record per user name in moodbuddy_users.json.
For every user, it stores cumulative counters for all six emotions,
negative-mood counters used by the warning logic, and a timestamped
history of every mood check-in. Returning users load the same record.
A different age is not accepted for an existing name, preventing
multiple records with conflicting ages for the same user.

Run with: python moodbuddy_all_emotions.py
"""

import json
import random
from datetime import datetime, timezone
from pathlib import Path


# The data file is created in the same folder as this Python program.
DATA_FILE = Path(__file__).resolve().with_name("moodbuddy_users.json")

mood_data = {
 
    # ---------------------------
    # CHILD (Age 4 - 8)
    # ---------------------------
    "Child": {
        "Happy": {
            "messages": [
                "Yay! You are feeling happy today! You are like a little sunshine!",
                "Your smile can light up the whole room. Keep shining bright!",
                "Happiness looks so good on you! You are doing amazing!",
                "You are glowing with joy today! That is so wonderful to see!"
            ],
            "activities": [
                "Draw a picture of what made you happy today.",
                "Do a happy dance for one whole minute!",
                "Share your happiness by giving someone a big high five or hug."
            ]
        },
        "Sad": {
            "messages": [
                "It is okay to feel sad sometimes. Even rainbows need a little rain.",
                "Feeling sad is normal. Your feelings matter and so do you.",
                "Everyone feels sad sometimes. You are brave for knowing how you feel.",
                "It is alright to cry. Let it out. Better days are always coming."
            ],
            "activities": [
                "Give your favourite toy or stuffed animal a big warm hug.",
                "Draw how you are feeling with your crayons or colours.",
                "Ask a grown-up to sit with you and read your favourite story."
            ]
        },
        "Angry": {
            "messages": [
                "Feeling angry is okay. Let us find a way to cool that feeling down.",
                "Big feelings like anger can be tough. You are strong enough to handle it.",
                "It is okay to be angry. Let us help that big feeling get smaller.",
                "Your anger is telling you something. Let us listen and then calm down."
            ],
            "activities": [
                "Stomp your feet 10 times to let those angry feelings out safely.",
                "Squeeze a pillow as tight as you can, then slowly let it go.",
                "Take 5 slow deep breaths like you are blowing out birthday candles."
            ]
        },
        "Lazy": {
            "messages": [
                "Feeling lazy just means your body is asking for a little rest. That is okay!",
                "Sometimes we all need a slow and easy day. You deserve rest too!",
                "It is fine to take it easy today. Even superheroes rest sometimes!",
                "A lazy feeling means your body wants to recharge. Let us do that gently!"
            ],
            "activities": [
                "Stretch your arms and legs wide like a big cat just waking up.",
                "Do 5 jumping jacks to gently wake your body up and get moving.",
                "Drink a glass of water and have a healthy snack to get some energy."
            ]
        },
        "Anxious": {
            "messages": [
                "Feeling worried is completely normal. You are safe and everything will be okay.",
                "It is okay to feel a little scared or nervous. You are very brave!",
                "Worries can feel really big but you are even bigger. You can get through this!",
                "Feeling anxious means you care. Let us take a breath and feel better together."
            ],
            "activities": [
                "Take 3 slow deep breaths and count to 5 slowly each time you breathe out.",
                "Tell a grown-up you trust exactly what is making you feel worried.",
                "Hug a soft toy, close your eyes, and think of your favourite happy place."
            ]
        },
        "Excited": {
            "messages": [
                "Wow you are so excited today! That energy is absolutely amazing!",
                "Your excitement is contagious! Everyone around you must be smiling too!",
                "So much excitement! You are totally ready to take on the world today!",
                "That excitement is sparkling right out of you! What a wonderful feeling!"
            ],
            "activities": [
                "Jump up and down and cheer as loud as you possibly can for 30 seconds!",
                "Tell your best friend or a family member what you are so excited about.",
                "Draw or colour a picture of what has got you feeling so excited today."
            ]
        }
    },
 
    # ---------------------------
    # PRETEEN (Age 9 - 13)
    # ---------------------------
    "Preteen": {
        "Happy": {
            "messages": [
                "You are in a great mood today! That happiness is totally well deserved.",
                "Feeling happy is the best feeling. Enjoy every single moment of it!",
                "Your positive energy today is incredible. Keep it going all day!",
                "Happiness suits you perfectly. Spread those good vibes around you!"
            ],
            "activities": [
                "Write 3 things that made you happy today in a notebook or journal.",
                "Call or message a friend and share this good mood with them.",
                "Listen to your absolute favourite song and sing along at the top of your lungs."
            ]
        },
        "Sad": {
            "messages": [
                "It is completely okay to feel sad. Your feelings are valid and very real.",
                "Everyone goes through tough days. You are definitely not alone in this.",
                "Feeling sad does not mean anything is wrong with you. It means you care.",
                "Let yourself feel sad for a little while. Brighter days always come."
            ],
            "activities": [
                "Write down exactly how you are feeling in a journal without any filters.",
                "Listen to a comforting playlist or a song that understands your mood.",
                "Talk to a friend or a family member you really trust about how you feel."
            ]
        },
        "Angry": {
            "messages": [
                "Anger is a signal that something important to you has been affected.",
                "It is okay to feel angry. What matters most is how we choose to handle it.",
                "Take a moment before reacting. Your feelings are valid but so are others.",
                "Anger is powerful energy. Let us channel it into something positive today."
            ],
            "activities": [
                "Write down what made you angry without filtering any of your thoughts.",
                "Go for a brisk walk or run around the block to release that built-up energy.",
                "Squeeze something soft like a stress ball or punch a pillow to let it out."
            ]
        },
        "Lazy": {
            "messages": [
                "Lazy days happen to absolutely everyone. Your body might just need a reset.",
                "Feeling unmotivated is totally normal. Start small and the energy will come.",
                "A lazy mood is never a permanent thing. One tiny step can change everything.",
                "Even on lazy days you can still achieve one small thing. That always counts!"
            ],
            "activities": [
                "Set a timer for just 10 minutes and knock out one small productive task.",
                "Step outside for a short walk around the block to wake your body up.",
                "Tidy up one small space like your desk or your shelf to feel accomplished."
            ]
        },
        "Anxious": {
            "messages": [
                "Anxiety is just your mind working a little overtime. Let us slow it down.",
                "Feeling anxious shows that you care deeply about things. You are not alone.",
                "Worries can feel overwhelming but you have handled hard things before.",
                "It is okay to feel anxious. Talking about it always helps let some pressure out."
            ],
            "activities": [
                "Write down your worries and next to each one write one possible small solution.",
                "Do 5 slow deep breaths counting 4 seconds in and 4 seconds out each time.",
                "Talk to a parent, teacher, or trusted adult about what is weighing on your mind."
            ]
        },
        "Excited": {
            "messages": [
                "You are absolutely buzzing with excitement today! That is so fantastic!",
                "That excitement is powerful energy. Use it to do something truly amazing!",
                "Excitement like yours is rare and wonderful. Enjoy absolutely every bit of it!",
                "You are completely fired up today! Ride that wave of excitement all day long!"
            ],
            "activities": [
                "Make a detailed plan or a list for what you are so excited about right now.",
                "Share your excitement with a close friend or a family member today.",
                "Put that energy into a creative project like drawing, writing, or crafting."
            ]
        }
    },
 
    # ---------------------------
    # TEEN (Age 14 - 19)
    # ---------------------------
    "Teen": {
        "Happy": {
            "messages": [
                "Love that energy! You are absolutely glowing today. Hold on to this feeling.",
                "Good moods like this deserve to be celebrated. You have earned this happiness.",
                "This happiness looks great on you. Let it carry you through the whole day.",
                "You are radiating great vibes today. The world around you feels it too."
            ],
            "activities": [
                "Text a friend something kind today and spread the good mood around.",
                "Write about what is making you happy so you can look back on it later.",
                "Do something you genuinely enjoy today just for yourself. You deserve it."
            ]
        },
        "Sad": {
            "messages": [
                "Feeling down is completely valid. You do not have to figure everything out alone.",
                "Sadness is not a weakness. It takes real courage to sit with your feelings.",
                "Not every day needs to be great. Today just needs to be gotten through.",
                "You are allowed to feel exactly how you feel. No explanations needed."
            ],
            "activities": [
                "Put on a playlist that matches how you feel then gradually switch to something uplifting.",
                "Write or journal everything on your mind without worrying about how it sounds.",
                "Reach out to one person you trust and just let them know you are having a hard day."
            ]
        },
        "Angry": {
            "messages": [
                "Anger means something important to you has been crossed. That feeling is real.",
                "It is valid to be angry. Breathe first and then decide how you want to respond.",
                "Your emotions are yours and they are valid. Just make sure they do not control your actions.",
                "Anger is energy. Once you cool down a little you can direct it somewhere powerful."
            ],
            "activities": [
                "Write everything you are feeling down without holding back. Do not send it to anyone.",
                "Go for a run, do push ups, or blast music to burn off that intense energy.",
                "Give yourself some space and then talk to someone you trust once you have calmed down."
            ]
        },
        "Lazy": {
            "messages": [
                "Burnout and low energy are real. Your mind and body might be asking for a break.",
                "Everyone hits a wall sometimes. Rest is not laziness. It is recovery.",
                "A slow day does not define your productivity. Be kind to yourself today.",
                "You cannot pour from an empty cup. Refill yourself first and the motivation will return."
            ],
            "activities": [
                "Step away from your screen for 30 minutes and do something offline you actually enjoy.",
                "Go outside even for just 10 minutes. Fresh air genuinely changes how you feel.",
                "Write one thing you want to accomplish today and focus only on that one thing."
            ]
        },
        "Anxious": {
            "messages": [
                "Anxiety is incredibly common at your age. You are far from alone in this feeling.",
                "Your brain is trying to protect you. Let us gently remind it that you are okay.",
                "Worrying about things means you care. Channel that caring into something actionable.",
                "Anxiety lies to you and makes things seem bigger than they are. You can handle this."
            ],
            "activities": [
                "Try the 5-4-3-2-1 method: name 5 things you see, 4 you hear, 3 you can touch.",
                "Write your specific worry down and then write one small thing you can do about it.",
                "Talk to someone you really trust or consider speaking to a school counsellor."
            ]
        },
        "Excited": {
            "messages": [
                "That excitement is real fuel. Do not waste it. Put it into action right now.",
                "You are buzzing and that energy is absolutely contagious. Enjoy every second of it.",
                "Big excitement deserves a big move. What is the one thing you can start right now?",
                "This feeling of excitement is precious. Ride it for as long as you possibly can."
            ],
            "activities": [
                "Start the thing you have been putting off while this motivation is at its peak.",
                "Share what has you excited with someone who will match your energy today.",
                "Write down exactly what you want to achieve while this excitement is fuelling you."
            ]
        }
    },
 
    # ---------------------------
    # YOUNG ADULT (Age 20 - 30)
    # ---------------------------
    "Young Adult": {
        "Happy": {
            "messages": [
                "Great to hear you are feeling good! Life is working in your favour right now.",
                "Enjoy this feeling fully. You have worked hard and this happiness is deserved.",
                "Positive energy like this is a gift. Make the most of every moment today.",
                "You are in a great headspace right now. Use it to do something meaningful today."
            ],
            "activities": [
                "Call or meet up with someone you care about and share this positive energy.",
                "Start something you have been putting off. This is the perfect moment to begin.",
                "Write down your top 3 goals and take one small step toward at least one of them today."
            ]
        },
        "Sad": {
            "messages": [
                "Low days are part of life. Acknowledging how you feel is already the first step.",
                "Sadness does not make you weak. It makes you human. Be gentle with yourself.",
                "You do not have to be okay all the time. Sit with this and let it pass naturally.",
                "Your feelings are completely valid. Reach out if you need support. You do not have to carry this alone."
            ],
            "activities": [
                "Get outside for a short walk. Moving your body genuinely shifts how you feel.",
                "Journal your thoughts without any judgement. Just get it all out on the page.",
                "Call or message someone you trust and let them know you need a little support today."
            ]
        },
        "Angry": {
            "messages": [
                "Frustration and anger are signals. Take a breath before you decide how to respond.",
                "Your anger is valid. What matters most is not letting it drive your decisions.",
                "Something has crossed a boundary for you. That feeling deserves to be understood.",
                "Take a step back. Process this emotion first and then respond from a calmer place."
            ],
            "activities": [
                "Write out everything you are feeling without filtering anything. Do not send it.",
                "Do a physical activity like a workout, a run, or even a brisk walk to release it.",
                "Talk through the situation with someone who can give you an honest outside perspective."
            ]
        },
        "Lazy": {
            "messages": [
                "Low motivation happens to everyone. Do not be too hard on yourself today.",
                "Rest is a legitimate need. If your body and mind need a break then take one.",
                "You cannot always operate at full speed. A slow day can actually be productive for your wellbeing.",
                "Start with just one small task. Momentum builds quickly once you get moving."
            ],
            "activities": [
                "Break your day into small blocks and focus on just one thing at a time.",
                "Go outside for even 10 minutes. Natural light and movement always help reset the mind.",
                "Drink water, have a proper meal, and check whether rest is really what you need right now."
            ]
        },
        "Anxious": {
            "messages": [
                "Anxiety at this stage of life is very common. You are not alone in feeling this way.",
                "Uncertainty is part of your twenties and thirties. It does not mean things are going wrong.",
                "Your mind is working overtime. Let us slow it down and focus on what you can actually control.",
                "Break the big worry into smaller parts. Each small part is far more manageable on its own."
            ],
            "activities": [
                "Write down exactly what is worrying you and separate what you can and cannot control.",
                "Practice box breathing: breathe in for 4, hold for 4, breathe out for 4, hold for 4.",
                "Speak to a close friend, a mentor, or a professional about what is on your mind."
            ]
        },
        "Excited": {
            "messages": [
                "Ride that wave! Big energy like this deserves an equally big move today.",
                "Excitement is motivation in its rawest form. Do not overthink it. Just start.",
                "This feeling is telling you that something matters to you. Listen to it and act.",
                "You are fired up and ready. Channel all of this into something you truly care about."
            ],
            "activities": [
                "Write down your top 3 goals right now while the motivation is running high.",
                "Take one concrete action today toward the thing that has you feeling this excited.",
                "Share your excitement with someone who will encourage and support your energy."
            ]
        }
    },
 
    # ---------------------------
    # ADULT (Age 31 - 50)
    # ---------------------------
    "Adult": {
        "Happy": {
            "messages": [
                "Wonderful! Savour this feeling. You deserve every bit of this happiness.",
                "Life feels good right now and that is worth appreciating fully. Hold on to it.",
                "Positive moments like these are precious. Make sure you are truly present in this one.",
                "Your happiness today is well earned. Share that warmth with the people around you."
            ],
            "activities": [
                "Spend quality time with someone you love and be fully present with them today.",
                "Do something just for yourself today, something you genuinely enjoy without any guilt.",
                "Write down what is making you happy so you can revisit it on the harder days."
            ]
        },
        "Sad": {
            "messages": [
                "Life carries real weight sometimes. Be gentle and patient with yourself today.",
                "Sadness is not something to push through or ignore. It deserves your attention.",
                "You have carried hard things before and you are still here. That says a lot about you.",
                "It is okay to not be okay. Reach out to someone. You do not have to carry this alone."
            ],
            "activities": [
                "Step outside for fresh air and a short walk even if just around the block.",
                "Do one small thing today that brings you comfort whether it is music, tea, or quiet.",
                "Reach out to someone you trust and let them know you are going through a hard time."
            ]
        },
        "Angry": {
            "messages": [
                "Something important to you has been affected and that is worth acknowledging.",
                "Your anger is valid. Take a breath before you act. Respond rather than react.",
                "Stress and responsibility build up over time. Releasing that pressure is important.",
                "Pause before you respond to anyone or anything. You will thank yourself for it later."
            ],
            "activities": [
                "Take 5 deep breaths slowly and then write down specifically what is frustrating you.",
                "Go for a walk, exercise, or do something physical to release the built-up tension.",
                "Give yourself space before responding and revisit the situation once you feel calmer."
            ]
        },
        "Lazy": {
            "messages": [
                "Low energy at this stage of life often means you are doing too much. Rest matters.",
                "A slow day is not a wasted day. Your body and mind are asking for something important.",
                "You carry a great deal every single day. Allowing yourself to rest is not a failure.",
                "Recharge properly today so that tomorrow you can show up as your best self again."
            ],
            "activities": [
                "Block out at least 30 minutes today that belongs entirely to you with no tasks at all.",
                "Do something gentle that restores you whether that is reading, walking, or just resting.",
                "Evaluate your current load and see if there is anything you can delegate or let go of."
            ]
        },
        "Anxious": {
            "messages": [
                "Worry often grows loudest in silence. Bringing it into the open always helps.",
                "You are managing a great deal and anxiety can be a natural response to that pressure.",
                "Focus on what you can actually control right now and gently release the rest for now.",
                "You have navigated difficult times before. You have more resilience than you realise."
            ],
            "activities": [
                "Write down your concern clearly and then write one small concrete next step you can take.",
                "Talk to a trusted person about what is weighing on you. A shared burden is lighter.",
                "Take a proper break from screens and to-do lists for at least 20 minutes today."
            ]
        },
        "Excited": {
            "messages": [
                "That spark of excitement is precious at any stage of life. Act on it today.",
                "Enthusiasm is contagious and you are full of it right now. Make the most of it.",
                "Something has clearly lit a fire in you. Do not let it fade. Move while you feel it.",
                "You are energised and ready. Use this feeling to start or restart something meaningful."
            ],
            "activities": [
                "Take one concrete step today toward the thing that has you feeling this energised.",
                "Write down your vision while it is vivid and plan the next three steps clearly.",
                "Share your excitement with someone who will genuinely celebrate and support it with you."
            ]
        }
    },
 
    # ---------------------------
    # SENIOR (Age 51 - 65)
    # ---------------------------
    "Senior": {
        "Happy": {
            "messages": [
                "What a wonderful feeling. You have earned every bit of this happiness today.",
                "This is a beautiful mood to be in. Cherish it and let it fill your whole day.",
                "Life has its seasons and right now you are in a beautiful one. Enjoy it fully.",
                "Your happiness today is a gift to everyone around you. Share it generously."
            ],
            "activities": [
                "Spend meaningful time with family or a close friend and be fully present with them.",
                "Do something you genuinely love today whether it is a hobby, a walk, or good company.",
                "Write down what is bringing you joy today so you can look back on this moment later."
            ]
        },
        "Sad": {
            "messages": [
                "It is completely okay to feel sad. Your feelings are always valid at every stage of life.",
                "Life has its heavy moments. Be kind to yourself and allow yourself to feel this.",
                "You have come through difficult times before. Your strength is greater than you feel right now.",
                "You do not have to face sadness alone. Reach out to someone who cares about you today."
            ],
            "activities": [
                "Sit with a warm cup of tea or coffee and give yourself permission to simply rest.",
                "Look through a cherished photo album or revisit a happy memory that brings you comfort.",
                "Call or visit someone you love and let them simply be with you today."
            ]
        },
        "Angry": {
            "messages": [
                "Your feelings are completely valid and deserve to be acknowledged fully.",
                "Frustration builds up when things do not go the way they should. That is understandable.",
                "Take your time before responding to anyone. A pause always serves you well.",
                "Something important to you has been impacted. Your feelings about that are entirely fair."
            ],
            "activities": [
                "Take slow deep breaths and spend a few quiet moments doing something calming you enjoy.",
                "Go for a gentle walk outside and let the fresh air help settle your thoughts.",
                "Write down what is bothering you privately and revisit it once you feel more settled."
            ]
        },
        "Lazy": {
            "messages": [
                "Rest is not laziness. At every age your body and mind deserve proper care and recovery.",
                "A slow day is a wise day sometimes. Listen to what your body is telling you today.",
                "You have given a great deal over the years. Resting today is absolutely well earned.",
                "Taking it easy is a form of self respect. Honour what your body needs right now."
            ],
            "activities": [
                "Rest comfortably and allow yourself to simply be without any pressure or to-do lists.",
                "Listen to music you love or read something that brings you genuine pleasure today.",
                "Do a few gentle stretches to get some circulation going without overdoing anything."
            ]
        },
        "Anxious": {
            "messages": [
                "Worry can feel heavier with age but you have more wisdom to face it than you realise.",
                "Concerns at this stage of life are natural. You do not have to carry them silently.",
                "Focus on what is within your control and gently release what is not. One step at a time.",
                "You have navigated uncertainty many times before. You are stronger than this feeling."
            ],
            "activities": [
                "Talk to a trusted family member or close friend about what is worrying you today.",
                "Write down your concern and then write one small thing you can actually do about it.",
                "Consider speaking with a doctor or counsellor if the anxiety feels persistent or heavy."
            ]
        },
        "Excited": {
            "messages": [
                "Wonderful! Excitement and enthusiasm are ageless. What a brilliant mood to be in!",
                "That spark of excitement keeps life feeling fresh and full of possibility. Cherish it!",
                "Something has clearly lit you up today and that energy is truly beautiful to see.",
                "Excitement at any age is a remarkable gift. Let it carry you forward into something great."
            ],
            "activities": [
                "Share your excitement with family or close friends. Your joy is genuinely contagious.",
                "Channel this energy into a project, hobby, or plan that you have been wanting to pursue.",
                "Write down what has you excited and take one small joyful step toward it today."
            ]
        }
    },
 
    # ---------------------------
    # ELDER (Age 66 and above)
    # ---------------------------
    "Elder": {
        "Happy": {
            "messages": [
                "What a wonderful mood to be in. You have seen enough of life to know how precious this is.",
                "Happiness suits you beautifully. Savour every moment of this lovely feeling today.",
                "You have earned every bit of this joy through a life well lived. Enjoy it completely.",
                "What a gift this feeling is. Let it warm your heart and everyone around you today."
            ],
            "activities": [
                "Call or visit a loved one and share this beautiful mood with them today.",
                "Do something that has always brought you joy whether a hobby, a walk, or good company.",
                "Sit quietly and reflect on a cherished memory that brings a smile to your face."
            ]
        },
        "Sad": {
            "messages": [
                "It is completely okay to feel sad. Your feelings are always real and always valid.",
                "You have lived through much and your heart is allowed to feel heavy sometimes.",
                "Sadness is part of a full life. Be tender with yourself and allow this feeling its space.",
                "You do not have to be strong all the time. Let someone who cares about you be there for you."
            ],
            "activities": [
                "Sit with a warm drink and allow yourself to simply rest without any expectations.",
                "Look through old photographs or letters that bring you warmth and fond memories.",
                "Reach out to a family member or close friend. Let them simply sit with you today."
            ]
        },
        "Angry": {
            "messages": [
                "Your feelings are entirely valid. You have every right to feel what you feel.",
                "Frustration is a natural response when things feel unfair or out of your control.",
                "Take your time and breathe slowly. There is no need to rush any response right now.",
                "You know better than most that this feeling will pass. Give it the time it needs."
            ],
            "activities": [
                "Sit in a quiet and comfortable space and breathe slowly until you feel more settled.",
                "Listen to calm and soothing music that you love until the feeling begins to ease.",
                "Write your thoughts down privately. Getting them out of your head always helps."
            ]
        },
        "Lazy": {
            "messages": [
                "Rest is not only okay it is necessary. Your body and mind deserve complete care.",
                "You have given so much over a lifetime. A slow and gentle day is truly well deserved.",
                "Resting is one of the wisest things you can do. Honour what your body is asking for.",
                "A quiet and easy day is a good day. There is absolutely nothing wrong with taking it slow."
            ],
            "activities": [
                "Rest as fully as you need to. Your wellbeing is and always has been what matters most.",
                "Listen to music you love, watch something enjoyable, or simply sit in peaceful quiet.",
                "Do gentle stretches if you feel up to it to keep your body comfortable and at ease."
            ]
        },
        "Anxious": {
            "messages": [
                "Worry can feel heavy but you carry with you a lifetime of wisdom to face it.",
                "You have moved through uncertainty many times before. You are still standing strong.",
                "Focus gently on what you can control today and let the rest go for now.",
                "You are not alone in this feeling. Please let someone close to you know how you feel."
            ],
            "activities": [
                "Talk to a family member or trusted friend about what is on your mind today.",
                "Sit quietly and take slow gentle breaths until you feel a little more at ease.",
                "Consider speaking with your doctor or a counsellor if the worry feels too heavy alone."
            ]
        },
        "Excited": {
            "messages": [
                "How absolutely wonderful! Excitement and joy are truly ageless. What a great mood!",
                "That enthusiasm of yours is one of life's greatest gifts. It is beautiful to see.",
                "Something has lit you up today and that spark is genuinely contagious. Wonderful!",
                "Your excitement reminds everyone around you that life is still full of beautiful things."
            ],
            "activities": [
                "Share this wonderful feeling with family or the people closest to you today.",
                "Do something that brings you genuine delight and pleasure today without any hesitation.",
                "Write down or tell someone about what has you feeling so excited and full of life."
            ]
        }
    }
}

# Fixed mood lists used throughout the program.
NEGATIVE_MOODS = ["Sad", "Angry", "Anxious"]
MOODS = ["Happy", "Sad", "Angry", "Lazy", "Anxious", "Excited"]

# Cumulative counters are never reset. They show the user's complete
# number of check-ins for every emotion across all program sessions.
DEFAULT_EMOTION_COUNTERS = {mood: 0 for mood in MOODS}

# These counters are separate because the original warning algorithm
# resets them when the user reports a non-negative emotion.
DEFAULT_NEGATIVE_COUNTERS = {"Sad": 0, "Angry": 0, "Anxious": 0}


# -------------------------------------------------------
# FUNCTION 1: Load all saved users from the JSON data file
# -------------------------------------------------------
def load_saved_data():
    """Return saved data, or an empty structure when no file exists."""
    if not DATA_FILE.exists():
        return {"users": {}}

    try:
        with DATA_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError):
        print("Saved data could not be read. A new data file will be used.")
        return {"users": {}}

    if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
        return {"users": {}}

    return data


# -------------------------------------------------------
# FUNCTION 2: Save all users safely back to the JSON file
# -------------------------------------------------------
def save_saved_data(data):
    """Write data through a temporary file to reduce partial-save risk."""
    temporary_file = DATA_FILE.with_suffix(".tmp")

    try:
        with temporary_file.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)
        temporary_file.replace(DATA_FILE)
    except OSError:
        print("Warning: MoodBuddy could not save your latest check-in.")


# -------------------------------------------------------
# FUNCTION 3: Validate the user's name
# -------------------------------------------------------
def get_valid_name():
    while True:
        name = input("Enter your name: ").strip()

        if name == "":
            print("Name cannot be blank.")
        elif len(name) > 20:
            print("Name must contain no more than 20 letters.")
        elif not name.isalpha():
            print("Use letters only. Do not use spaces, numbers, or symbols.")
        else:
            return name


# -------------------------------------------------------
# FUNCTION 4: Validate the user's age
# -------------------------------------------------------
def get_valid_age(name):
    while True:
        age_input = input(f"How old are you, {name}? ").strip()

        if not age_input.isdigit():
            print("Please enter age as a number.")
            continue

        age = int(age_input)

        if age < 4 or age > 100:
            print("Please enter an age between 4 and 100.")
        else:
            return age


# -------------------------------------------------------
# FUNCTION 5: Convert age into an age-range label
# -------------------------------------------------------
def get_age_group(age):
    if 4 <= age <= 8:
        return "Child"
    elif 9 <= age <= 13:
        return "Preteen"
    elif 14 <= age <= 19:
        return "Teen"
    elif 20 <= age <= 30:
        return "Young Adult"
    elif 31 <= age <= 50:
        return "Adult"
    elif 51 <= age <= 65:
        return "Senior"
    else:
        return "Elder"


# -------------------------------------------------------
# FUNCTION 6: Clean saved counters and mood history
# -------------------------------------------------------
def clean_emotion_counters(saved_counters, legacy_negative_counters=None):
    """Return valid cumulative counters for all six emotions.

    Older MoodBuddy data files may contain only ``negative_counters``.
    When that happens, the available Sad/Angry/Anxious values are copied
    into the new all-emotion counter structure as a one-time migration.
    """
    counters = DEFAULT_EMOTION_COUNTERS.copy()

    if isinstance(saved_counters, dict):
        for mood in MOODS:
            value = saved_counters.get(mood, 0)
            if isinstance(value, int) and value >= 0:
                counters[mood] = value
    elif isinstance(legacy_negative_counters, dict):
        for mood in NEGATIVE_MOODS:
            value = legacy_negative_counters.get(mood, 0)
            if isinstance(value, int) and value >= 0:
                counters[mood] = value

    return counters


def clean_negative_counters(saved_counters):
    """Return valid counters used only for repeated-negative warnings."""
    counters = DEFAULT_NEGATIVE_COUNTERS.copy()

    if isinstance(saved_counters, dict):
        for mood in NEGATIVE_MOODS:
            value = saved_counters.get(mood, 0)
            if isinstance(value, int) and value >= 0:
                counters[mood] = value

    return counters


def clean_check_in_history(saved_history):
    """Keep only valid timestamped mood-history entries."""
    history = []

    if not isinstance(saved_history, list):
        return history

    for entry in saved_history:
        if not isinstance(entry, dict):
            continue

        mood = entry.get("mood")
        checked_in_at = entry.get("checked_in_at")

        if mood not in MOODS or not isinstance(checked_in_at, str):
            continue

        cleaned_entry = {
            "checked_in_at": checked_in_at,
            "mood": mood,
        }

        age_group = entry.get("age_group")
        if isinstance(age_group, str):
            cleaned_entry["age_group"] = age_group

        history.append(cleaned_entry)

    return history


# -------------------------------------------------------
# FUNCTION 7: Find a saved user or create one new record
# -------------------------------------------------------
def get_or_create_user(saved_data):
    """
    The normalised name is the unique key.
    Therefore 'Sam', 'sam', and 'SAM' refer to the same saved user.
    """
    name = get_valid_name()
    age = get_valid_age(name)
    user_key = name.casefold()
    users = saved_data["users"]

    if user_key in users:
        user = users[user_key]
        saved_age = user.get("age")

        # Do not accept a different age for an already-saved name.
        while age != saved_age:
            print()
            print(f'A user named "{user.get("name", name)}" already exists.')
            print("The age entered does not match the saved age.")
            print("Please enter the original age for this user.")
            age = get_valid_age(name)

        user["name"] = user.get("name", name)
        user["age"] = saved_age
        user["emotion_counters"] = clean_emotion_counters(
            user.get("emotion_counters"),
            user.get("negative_counters"),
        )
        user["negative_counters"] = clean_negative_counters(
            user.get("negative_counters")
        )
        user["check_in_history"] = clean_check_in_history(
            user.get("check_in_history")
        )
        user["total_check_ins"] = sum(user["emotion_counters"].values())

        print(f"Welcome back, {user['name']}! Your saved data was loaded.")
        return user_key, user, False

    # No matching name exists, so create exactly one new record.
    user = {
        "name": name,
        "age": age,
        "emotion_counters": DEFAULT_EMOTION_COUNTERS.copy(),
        "negative_counters": DEFAULT_NEGATIVE_COUNTERS.copy(),
        "check_in_history": [],
        "total_check_ins": 0,
        "last_mood": None,
        "last_check_in": None,
    }
    users[user_key] = user
    save_saved_data(saved_data)

    print(f"Welcome, {name}! A new MoodBuddy record was created.")
    return user_key, user, True


# -------------------------------------------------------
# FUNCTION 8: Ask for a valid mood
# -------------------------------------------------------
def get_valid_mood():
    print("\nHow is your mood today?")
    print("1. Happy")
    print("2. Sad")
    print("3. Angry")
    print("4. Lazy")
    print("5. Anxious")
    print("6. Excited")

    mood_choices = {
        "1": "Happy",
        "2": "Sad",
        "3": "Angry",
        "4": "Lazy",
        "5": "Anxious",
        "6": "Excited",
    }

    while True:
        choice = input("Choose a mood from 1 to 6: ").strip()
        if choice in mood_choices:
            return mood_choices[choice]
        print("Please enter a number between 1 and 6.")


# -------------------------------------------------------
# FUNCTION 9: Display the selected message and activity
# -------------------------------------------------------
def show_response(name, age_group, mood, negative_count=None):
    data = mood_data[age_group][mood]

    if mood in NEGATIVE_MOODS:
        # Count 1 -> message 1, count 2 -> message 2,
        # count 3 -> message 3, and count 4+ -> message 4.
        message_index = min(negative_count, 4) - 1
        message = data["messages"][message_index]
    else:
        # Non-negative moods use a random one of the four messages.
        message = random.choice(data["messages"])

    activity = random.choice(data["activities"])

    print("\n" + "=" * 60)
    print(f"MoodBuddy response for {name}")
    print(f"Mood: {mood}")
    print()
    print(message)
    print()
    print("Suggested activity:")
    print(activity)
    print("=" * 60)


# -------------------------------------------------------
# FUNCTION 10: Show a warning for repeated negative moods
# -------------------------------------------------------
def show_warning(mood, name):
    print("\n" + "*" * 60)

    if mood == "Sad":
        print(f"{name}, you have checked in as sad several times.")
        print("Please consider talking to a trusted person who can support you.")
    elif mood == "Angry":
        print(f"{name}, anger has appeared in several check-ins.")
        print("Pause, create some space, and speak with someone you trust.")
    elif mood == "Anxious":
        print(f"{name}, anxiety has appeared in several check-ins.")
        print("You do not have to manage it alone. Reach out for support.")

    print("MoodBuddy offers general encouragement and is not emergency care.")
    print("*" * 60)


# -------------------------------------------------------
# FUNCTION 11: Ask whether to continue or quit
# -------------------------------------------------------
def get_continue_choice():
    while True:
        print("\nDo you want to check in again or quit?")
        print("1. Check in again")
        print("2. Quit")
        choice = input("Enter 1 or 2: ").strip()

        if choice in ("1", "2"):
            return choice

        print("Please enter 1 or 2.")


# -------------------------------------------------------
# FUNCTION 12: Main program
# -------------------------------------------------------
def main():
    print("=" * 60)
    print("                 Welcome to MoodBuddy!")
    print("=" * 60)

    saved_data = load_saved_data()
    user_key, user, _ = get_or_create_user(saved_data)

    name = user["name"]
    age = user["age"]
    age_group = get_age_group(age)
    emotion_counters = user["emotion_counters"]
    negative_counters = user["negative_counters"]
    check_in_history = user["check_in_history"]

    if 66 <= age <= 100:
        print("We are glad you are here. Your experience and feelings matter.")

    while True:
        mood = get_valid_mood()

        # Track every emotion cumulatively. These values are never reset.
        emotion_counters[mood] += 1

        if mood in NEGATIVE_MOODS:
            negative_counters[mood] += 1
            current_count = negative_counters[mood]
            show_response(name, age_group, mood, current_count)

            if current_count >= 3:
                show_warning(mood, name)
        else:
            # Only the warning counters reset. The cumulative counters above
            # continue to preserve the user's complete emotion totals.
            for negative_mood in NEGATIVE_MOODS:
                negative_counters[negative_mood] = 0

            show_response(name, age_group, mood)

        # Save a timestamped record of this individual check-in.
        check_in_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
        check_in_history.append(
            {
                "checked_in_at": check_in_time,
                "mood": mood,
                "age_group": age_group,
            }
        )

        # Save all counters and history after every check-in.
        user["emotion_counters"] = emotion_counters
        user["negative_counters"] = negative_counters
        user["check_in_history"] = check_in_history
        user["total_check_ins"] = sum(emotion_counters.values())
        user["last_mood"] = mood
        user["last_check_in"] = check_in_time
        saved_data["users"][user_key] = user
        save_saved_data(saved_data)

        print("\nYour complete emotion data has been saved.")
        print(f"Total saved check-ins: {user['total_check_ins']}")

        if get_continue_choice() == "2":
            break

    print(f"\nSee you soon, {name}!")


if __name__ == "__main__":
    main()
