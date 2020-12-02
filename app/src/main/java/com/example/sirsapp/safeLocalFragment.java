package com.example.sirsapp;

import android.os.Bundle;

import androidx.fragment.app.Fragment;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

public class safeLocalFragment extends Fragment {


    public safeLocalFragment() {
        // Required empty public constructor
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {

        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment

        View view = inflater.inflate(R.layout.fragment_safe_local, container, false);

        Button button = view.findViewById(R.id.safeLocalButton);
        button.setOnClickListener(this::changeLocalStatus);

        return view;
    }

    public void changeLocalStatus(View view){
        Button button = view.findViewById(R.id.safeLocalButton);
        View parent_view = (View) button.getParent();
        TextView textView = parent_view.findViewById(R.id.safeLocalTextView);
        ImageView image = parent_view.findViewById(R.id.safeLocalIcon);

        boolean markAsSafe = textView.getText().equals(getResources().getString(R.string.this_location_is_unsafe));

        textView.setText(markAsSafe ? R.string.this_location_is_safe : R.string.this_location_is_unsafe);
        button.setText(markAsSafe ? R.string.safeLocalMarkUnsafeButton : R.string.safeLocalMarkAsSafe);
        button.setBackgroundColor(markAsSafe ? getResources().getColor(R.color.safeLocalMarkUnsafeButton, null) : getResources().getColor(R.color.safeLocalMakeSafeButton, null));
        image.setImageResource(markAsSafe ? R.drawable.ic_baseline_check_24 : R.drawable.ic_baseline_clear_24);
        parent_view.setBackgroundColor(markAsSafe ? getResources().getColor(R.color.safeLocalSafeLocation, null) : getResources().getColor(R.color.safeLocalUnsafeBackgroud, null));
    }
}