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
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

public class safeLocalFragment extends Fragment {

    private List<Integer> wifiIds;

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

        boolean status = ((DrawerActivity)getActivity()).checkCurrentWifi().equals("SAFE");
        updateUI(view, status);

        Button button = view.findViewById(R.id.safeLocalButton);
        button.setOnClickListener(this::changeLocalStatus);

        return view;
    }

    public void changeLocalStatus(View view){
        Button button = view.findViewById(R.id.safeLocalButton);
        View parent_view = (View) button.getParent();
        TextView textView = parent_view.findViewById(R.id.safeLocalTextView);
        boolean markAsSafe = textView.getText().equals(getResources().getString(R.string.this_location_is_unsafe));
        try {
            int wifiId = ((DrawerActivity)getActivity()).getWifiId();
            if (markAsSafe)
                ((DrawerActivity)getActivity()).addSafeWifi(wifiId);
            else
                ((DrawerActivity)getActivity()).removeSafeWifi(wifiId);
            new Thread(() -> {
                try {
                    if(!((DrawerActivity)getActivity()).updateLocalStatus(markAsSafe ? "OK" : "NO"))
                        getActivity().runOnUiThread(() -> { Toast.makeText(getContext(), "Could not update internal server", Toast.LENGTH_LONG).show(); });
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
            // send information to auth
        } catch (Exception e) {
            getActivity().runOnUiThread(() -> { Toast.makeText(getContext(), "An error occured, pleas try again!", Toast.LENGTH_LONG).show(); });
        }
        updateUI(view, markAsSafe);
    }

    private void updateUI(View view, boolean safe) {
        Button button = view.findViewById(R.id.safeLocalButton);
        View parent_view = (View) button.getParent();
        TextView textView = parent_view.findViewById(R.id.safeLocalTextView);
        ImageView image = parent_view.findViewById(R.id.safeLocalIcon);

        textView.setText(safe ? R.string.this_location_is_safe : R.string.this_location_is_unsafe);
        button.setText(safe ? R.string.safeLocalMarkUnsafeButton : R.string.safeLocalMarkAsSafe);
        button.setBackgroundColor(safe ? getResources().getColor(R.color.safeLocalMarkUnsafeButton, null) : getResources().getColor(R.color.safeLocalMakeSafeButton, null));
        image.setImageResource(safe ? R.drawable.ic_baseline_check_24 : R.drawable.ic_baseline_clear_24);
        parent_view.setBackgroundColor(safe ? getResources().getColor(R.color.safeLocalSafeLocation, null) : getResources().getColor(R.color.safeLocalUnsafeBackgroud, null));
    }


}